//! Electrum protocol client for Bitcoin/Litecoin chain access.
//!
//! The backend runs no BTC/LTC full node, so balance, UTXO, history,
//! chain-tip, verbose-transaction, fee-estimate, and broadcast queries are
//! served by external Electrum/Fulcrum servers named in [`UtxoConfig`].
//!
//! Every byte these servers return is treated as hostile — a server may be
//! malicious, compromised, or MITM'd. The client is hardened accordingly:
//!
//!   * **TLS is verified** against the webpki root store *with hostname
//!     checking*. There is no accept-any-certificate path.
//!   * Each response read is **size-bounded** and each exchange is wrapped in a
//!     **timeout** (no OOM, no slowloris).
//!   * Addresses are decoded with the audited [`bech32`] crate (full checksum +
//!     bech32m + witness version) and base58check (checksum + network), then
//!     validated against the configured coin/network.
//!   * On-chain decimal amounts pass through a **fallible checked converter**
//!     that rejects non-finite/negative/overflowing values; sums use
//!     `checked_add`. A hostile peer cannot drive a balance to `0` or `u64::MAX`.
//!   * Each JSON-RPC response id is **correlated** with its request.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::seq::SliceRandom;
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{instrument, warn};

use crate::config::UtxoConfig;
use crate::error::AppError;

/// TCP + TLS connect deadline per server.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for the write-request / read-response exchange on a connected stream.
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard cap on a single Electrum response line. Even a large verbose tx or a
/// busy address's full history sits well under this; the cap turns a hostile
/// unbounded stream into a clean error instead of unbounded memory growth.
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// The coin + network an [`ElectrumClient`] is bound to. Used to validate that
/// a queried address actually belongs to this chain (reject ltc-on-btc,
/// testnet-on-mainnet) before it is turned into a scripthash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtxoNetwork {
    BitcoinMainnet,
    BitcoinTestnet,
    LitecoinMainnet,
    LitecoinTestnet,
}

impl UtxoNetwork {
    /// Bitcoin variant for a `mainnet`/`testnet` config string.
    pub fn bitcoin(network: &str) -> Result<Self, AppError> {
        match network {
            "mainnet" => Ok(Self::BitcoinMainnet),
            "testnet" => Ok(Self::BitcoinTestnet),
            other => Err(AppError::ConfigError(format!(
                "unknown bitcoin network: {other}"
            ))),
        }
    }

    /// Litecoin variant for a `mainnet`/`testnet` config string.
    pub fn litecoin(network: &str) -> Result<Self, AppError> {
        match network {
            "mainnet" => Ok(Self::LitecoinMainnet),
            "testnet" => Ok(Self::LitecoinTestnet),
            other => Err(AppError::ConfigError(format!(
                "unknown litecoin network: {other}"
            ))),
        }
    }

    /// Expected bech32 human-readable part for native-segwit addresses.
    fn segwit_hrp(self) -> &'static str {
        match self {
            Self::BitcoinMainnet => "bc",
            Self::BitcoinTestnet => "tb",
            Self::LitecoinMainnet => "ltc",
            Self::LitecoinTestnet => "tltc",
        }
    }

    /// base58check version byte for P2PKH on this network.
    fn p2pkh_version(self) -> u8 {
        match self {
            Self::BitcoinMainnet => 0x00,
            Self::BitcoinTestnet => 0x6f,
            Self::LitecoinMainnet => 0x30,
            Self::LitecoinTestnet => 0x6f,
        }
    }

    /// base58check version byte(s) for P2SH on this network. Litecoin has both
    /// the modern (`0x32`) and the legacy Bitcoin-shared (`0x05`) prefix.
    fn p2sh_versions(self) -> &'static [u8] {
        match self {
            Self::BitcoinMainnet => &[0x05],
            Self::BitcoinTestnet => &[0xc4],
            Self::LitecoinMainnet => &[0x32, 0x05],
            Self::LitecoinTestnet => &[0x3a, 0xc4],
        }
    }
}

/// Electrum client bound to one coin/network, querying a primary server with
/// randomized fallbacks. Cheap to clone (TLS connector and id counter are
/// shared via `Arc`); construct once and reuse.
#[derive(Clone)]
pub struct ElectrumClient {
    network: UtxoNetwork,
    primary: Option<ServerUrl>,
    fallbacks: Vec<ServerUrl>,
    /// Built once from the webpki root store and reused for every TLS dial.
    tls: TlsConnector,
    /// Monotonic JSON-RPC request id, shared across clones for correlation.
    next_id: Arc<AtomicU64>,
}

/// Confirmed/unconfirmed balance in satoshis (integer fields straight off the
/// wire — no float round-trip).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectrumBalance {
    pub confirmed: u64,
    pub unconfirmed: i64,
}

/// An unspent output (integer-sat `value` straight off the wire).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectrumUtxo {
    pub tx_hash: String,
    pub tx_pos: u64,
    pub value: u64,
    pub height: u64,
}

/// A transaction-history entry for an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectrumHistoryEntry {
    pub tx_hash: String,
    /// Block height; `0` (or negative for unconfirmed-with-unconfirmed-parents).
    pub height: i64,
    #[serde(default)]
    pub fee: Option<u64>,
}

/// Best-chain tip header from `blockchain.headers.subscribe`; the chain-height
/// source for confirmation counting (the backend runs no node).
#[derive(Debug, Clone, Deserialize)]
struct TipHeaderResult {
    height: i64,
}

/// Verbose transaction from `blockchain.transaction.get` (verbose=true).
#[derive(Debug, Clone, Deserialize)]
pub struct VerboseTransaction {
    pub txid: String,
    #[serde(default)]
    pub vin: Vec<VerboseVin>,
    #[serde(default)]
    pub vout: Vec<VerboseVout>,
}

/// A transaction input. Modern servers (Fulcrum) resolve `prevout`; public
/// ElectrumX servers carry only the `txid:vout` reference.
#[derive(Debug, Clone, Deserialize)]
pub struct VerboseVin {
    pub txid: Option<String>,
    pub vout: Option<u32>,
    #[serde(default)]
    pub prevout: Option<Prevout>,
}

/// A resolved previous output (value is decimal BTC/LTC, not satoshis).
#[derive(Debug, Clone, Deserialize)]
pub struct Prevout {
    pub value: f64,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKeyInfo,
}

/// A transaction output (value is decimal BTC/LTC, not satoshis).
#[derive(Debug, Clone, Deserialize)]
pub struct VerboseVout {
    pub value: f64,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKeyInfo,
}

/// scriptPubKey address info, accepting both the modern single-`address` form
/// and the legacy `addresses` array.
#[derive(Debug, Clone, Deserialize)]
pub struct ScriptPubKeyInfo {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub addresses: Option<Vec<String>>,
}

impl ScriptPubKeyInfo {
    /// The address from this scriptPubKey, checking both wire formats.
    pub fn get_address(&self) -> Option<&str> {
        self.address.as_deref().or_else(|| {
            self.addresses
                .as_ref()
                .and_then(|a| a.first().map(|s| s.as_str()))
        })
    }
}

impl VerboseTransaction {
    /// Total received (in satoshis) at `address`, summed across this tx's
    /// outputs to that address. Outputs are unambiguous, so this is exact.
    ///
    /// Returns an error if any matching output carries a non-finite, negative,
    /// or overflowing amount (a hostile/corrupt server response) rather than
    /// silently coercing it.
    pub fn total_received_at(&self, address: &str) -> Result<u64, AppError> {
        let mut total: u64 = 0;
        for v in &self.vout {
            if v.script_pub_key.get_address() == Some(address) {
                total = total
                    .checked_add(checked_btc_to_sat(v.value)?)
                    .ok_or_else(|| AppError::NodeError("output amount sum overflow".into()))?;
            }
        }
        Ok(total)
    }

    /// Total sent FROM `address` in this tx, computed *exactly* from resolved
    /// prevout data.
    ///
    /// Returns `Ok(None)` when the server did not resolve prevouts (typical of
    /// public ElectrumX): without input amounts the sent value cannot be
    /// determined unambiguously, and the client never guesses — declining to
    /// answer is correct, where the old heuristic mislabeled a
    /// receive-with-change as a send. Fulcrum-class servers give an exact
    /// `Ok(Some(_))`.
    ///
    /// `Some` always means *exact*: an answer requires EVERY input to carry a
    /// resolved prevout. A response that resolves only some inputs (a partial or
    /// hostile server) must not yield a value that looks exact while silently
    /// omitting the unresolved inputs — so any unresolved input forces `None`. A
    /// tx with no inputs (coinbase-like) is an exact zero.
    pub fn total_sent_from(&self, address: &str) -> Result<Option<u64>, AppError> {
        if self.vin.iter().any(|vin| vin.prevout.is_none()) {
            return Ok(None);
        }
        let mut total: u64 = 0;
        for vin in &self.vin {
            if let Some(prevout) = &vin.prevout {
                if prevout.script_pub_key.get_address() == Some(address) {
                    total = total
                        .checked_add(checked_btc_to_sat(prevout.value)?)
                        .ok_or_else(|| AppError::NodeError("input amount sum overflow".into()))?;
                }
            }
        }
        Ok(Some(total))
    }
}

/// Convert a decimal BTC/LTC amount (as delivered in a verbose tx) to integer
/// satoshis, rejecting anything that cannot be represented exactly and safely.
///
/// `(value * 1e8) as u64` is *saturating and silent*: `NaN -> 0`, `-1 -> 0`,
/// `+Inf/huge -> u64::MAX`. A hostile server could thereby set any displayed
/// amount to zero or to 18.4 quintillion. This converter rejects non-finite,
/// negative, and out-of-range inputs instead. The `2^53` ceiling (~90M BTC,
/// above any real coin's supply) is exactly where `f64` stops representing
/// integers losslessly, so a passing value converts to `u64` with no rounding
/// surprise.
fn checked_btc_to_sat(value: f64) -> Result<u64, AppError> {
    const MAX_EXACT_SAT: f64 = 9_007_199_254_740_992.0; // 2^53
    if !value.is_finite() || value < 0.0 {
        return Err(AppError::NodeError(
            "non-finite or negative amount from Electrum server".into(),
        ));
    }
    let sats = (value * 100_000_000.0).round();
    if sats >= MAX_EXACT_SAT {
        return Err(AppError::NodeError(
            "amount out of range from Electrum server".into(),
        ));
    }
    Ok(sats as u64)
}

/// Render untrusted upstream text safe for a private (redacted-publicly) log or
/// error string: drop control characters that could forge log lines, and cap
/// the length to bound volume. Operates on `chars`, never byte-indexing.
fn truncate_for_log(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// JSON-RPC request frame.
#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: &'a [serde_json::Value],
    id: u64,
}

/// JSON-RPC response frame. Unknown fields (e.g. `jsonrpc`) are ignored; a
/// missing `result`/`error` deserializes to `None`.
#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcError {
    #[serde(default)]
    message: String,
}

/// A parsed `ssl://`/`tls://`/`tcp://` server endpoint.
#[derive(Debug, Clone)]
struct ServerUrl {
    host: String,
    port: u16,
    use_ssl: bool,
}

impl ElectrumClient {
    /// Build a client for an explicit coin/network from its `UtxoConfig`.
    /// Server URLs are parsed once here, so a malformed endpoint fails fast at
    /// startup rather than per request.
    pub fn new(network: UtxoNetwork, cfg: &UtxoConfig) -> Result<Self, AppError> {
        let primary = cfg
            .electrum_primary
            .as_deref()
            .map(parse_server_url)
            .transpose()?;
        let fallbacks = cfg
            .electrum_fallbacks
            .iter()
            .map(|u| parse_server_url(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            network,
            primary,
            fallbacks,
            tls: build_tls_connector(),
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    /// Build a Bitcoin client from its `UtxoConfig` (network from `cfg.network`).
    pub fn bitcoin(cfg: &UtxoConfig) -> Result<Self, AppError> {
        Self::new(UtxoNetwork::bitcoin(&cfg.network)?, cfg)
    }

    /// Build a Litecoin client from its `UtxoConfig` (network from `cfg.network`).
    pub fn litecoin(cfg: &UtxoConfig) -> Result<Self, AppError> {
        Self::new(UtxoNetwork::litecoin(&cfg.network)?, cfg)
    }

    /// Confirmed/unconfirmed balance for an address.
    #[instrument(skip_all, fields(net = ?self.network))]
    pub async fn get_balance(&self, address: &str) -> Result<ElectrumBalance, AppError> {
        let sh = self.address_to_scripthash(address)?;
        self.call("blockchain.scripthash.get_balance", vec![sh.into()])
            .await
    }

    /// Unspent outputs for an address.
    #[instrument(skip_all, fields(net = ?self.network))]
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<ElectrumUtxo>, AppError> {
        let sh = self.address_to_scripthash(address)?;
        self.call("blockchain.scripthash.listunspent", vec![sh.into()])
            .await
    }

    /// Confirmed + mempool transaction history for an address.
    #[instrument(skip_all, fields(net = ?self.network))]
    pub async fn get_history(&self, address: &str) -> Result<Vec<ElectrumHistoryEntry>, AppError> {
        let sh = self.address_to_scripthash(address)?;
        self.call("blockchain.scripthash.get_history", vec![sh.into()])
            .await
    }

    /// Current best-chain tip height via `blockchain.headers.subscribe`.
    #[instrument(skip_all, fields(net = ?self.network))]
    pub async fn get_tip_height(&self) -> Result<i64, AppError> {
        let header: TipHeaderResult = self.call("blockchain.headers.subscribe", vec![]).await?;
        Ok(header.height)
    }

    /// Verbose (decoded) transaction by txid.
    #[instrument(skip_all, fields(net = ?self.network))]
    pub async fn get_transaction_verbose(
        &self,
        txid: &str,
    ) -> Result<VerboseTransaction, AppError> {
        self.call("blockchain.transaction.get", vec![txid.into(), true.into()])
            .await
    }

    /// Broadcast a signed raw transaction; returns the txid.
    #[instrument(skip_all, fields(net = ?self.network))]
    pub async fn broadcast_transaction(&self, tx_hex: &str) -> Result<String, AppError> {
        self.call("blockchain.transaction.broadcast", vec![tx_hex.into()])
            .await
    }

    /// Estimate the fee rate (sat/vB) for confirmation within `blocks` blocks.
    /// Returns `None` when the server cannot estimate; non-finite or absurd
    /// values are rejected/clamped so a hostile response cannot produce an
    /// under- or over-fee transaction.
    #[instrument(skip_all, fields(net = ?self.network))]
    pub async fn estimate_fee(&self, blocks: u32) -> Result<Option<f64>, AppError> {
        /// 10k sat/vB is already far above any sane real fee.
        const MAX_SAT_PER_VB: f64 = 10_000.0;
        let btc_per_kb: f64 = self
            .call("blockchain.estimatefee", vec![blocks.into()])
            .await?;
        if !btc_per_kb.is_finite() || btc_per_kb <= 0.0 {
            return Ok(None); // -1 / 0 / non-finite => estimation unavailable
        }
        // BTC/kB -> sat/vB: * 1e8 / 1000 = * 1e5.
        let sat_per_vb = btc_per_kb * 100_000.0;
        if !sat_per_vb.is_finite() || sat_per_vb <= 0.0 {
            Ok(None)
        } else {
            Ok(Some(sat_per_vb.min(MAX_SAT_PER_VB)))
        }
    }

    /// Issue one JSON-RPC call, trying the primary server then randomized
    /// fallbacks. Failover, id correlation, and error mapping live here so each
    /// public method stays a thin wrapper.
    async fn call<T>(&self, method: &str, params: Vec<serde_json::Value>) -> Result<T, AppError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let servers = self.servers_in_order();
        if servers.is_empty() {
            return Err(AppError::NodeError("no Electrum server configured".into()));
        }

        let mut last_err = AppError::NodeError("all Electrum servers failed".into());
        for server in servers {
            match self.try_call::<T>(&server, method, &params, id).await {
                Ok(value) => return Ok(value),
                Err(e) => {
                    // host/port are operator config (not attacker body); the
                    // detailed `inner` is logged privately by AppError.
                    warn!(host = %server.host, port = server.port, method, "Electrum server query failed");
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    /// Primary first, then fallbacks in randomized order.
    fn servers_in_order(&self) -> Vec<ServerUrl> {
        let mut ordered = Vec::with_capacity(1 + self.fallbacks.len());
        if let Some(p) = &self.primary {
            ordered.push(p.clone());
        }
        let mut fallbacks = self.fallbacks.clone();
        fallbacks.shuffle(&mut rand::thread_rng());
        ordered.extend(fallbacks);
        ordered
    }

    /// One attempt against one server: connect (TLS or TCP), exchange, and map
    /// the JSON-RPC envelope into a typed result.
    async fn try_call<T>(
        &self,
        server: &ServerUrl,
        method: &str,
        params: &[serde_json::Value],
        id: u64,
    ) -> Result<T, AppError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response: JsonRpcResponse<T> = if server.use_ssl {
            self.exchange_ssl(server, method, params, id).await?
        } else {
            self.exchange_tcp(server, method, params, id).await?
        };
        into_result(response, id)
    }

    /// Exchange over plaintext TCP.
    async fn exchange_tcp<T>(
        &self,
        server: &ServerUrl,
        method: &str,
        params: &[serde_json::Value],
        id: u64,
    ) -> Result<JsonRpcResponse<T>, AppError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let tcp = timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((server.host.as_str(), server.port)),
        )
        .await
        .map_err(|_| AppError::NodeError("Electrum TCP connect timed out".into()))?
        .map_err(|e| AppError::NodeError(format!("Electrum TCP connect failed: {e}")))?;
        send_request_on_stream(tcp, method, params, id).await
    }

    /// Exchange over TLS, with full webpki chain + hostname verification.
    async fn exchange_ssl<T>(
        &self,
        server: &ServerUrl,
        method: &str,
        params: &[serde_json::Value],
        id: u64,
    ) -> Result<JsonRpcResponse<T>, AppError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let tcp = timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((server.host.as_str(), server.port)),
        )
        .await
        .map_err(|_| AppError::NodeError("Electrum TCP connect timed out".into()))?
        .map_err(|e| AppError::NodeError(format!("Electrum TCP connect failed: {e}")))?;

        // `ServerName` from the configured host drives rustls's hostname check
        // against the presented certificate.
        let domain = ServerName::try_from(server.host.clone())
            .map_err(|_| AppError::NodeError("invalid Electrum server name".into()))?;
        let tls = timeout(CONNECT_TIMEOUT, self.tls.connect(domain, tcp))
            .await
            .map_err(|_| AppError::NodeError("Electrum TLS handshake timed out".into()))?
            .map_err(|e| AppError::NodeError(format!("Electrum TLS handshake failed: {e}")))?;
        send_request_on_stream(tls, method, params, id).await
    }

    /// SHA256(scriptPubKey) reversed to little-endian, hex-encoded — the
    /// Electrum scripthash addressing convention.
    fn address_to_scripthash(&self, address: &str) -> Result<String, AppError> {
        let script = self.address_to_script(address)?;
        let hash = Sha256::digest(&script);
        let reversed: Vec<u8> = hash.iter().rev().copied().collect();
        Ok(hex::encode(reversed))
    }

    /// Decode an address to its scriptPubKey, enforcing the configured network.
    fn address_to_script(&self, address: &str) -> Result<Vec<u8>, AppError> {
        let hrp = self.network.segwit_hrp();
        // Decide segwit-vs-base58 intent without byte-indexing untrusted input:
        // `strip_prefix`/`starts_with` are char-boundary safe.
        let looks_segwit = address
            .to_ascii_lowercase()
            .strip_prefix(hrp)
            .is_some_and(|rest| rest.starts_with('1'));
        if looks_segwit {
            self.segwit_to_script(address)
        } else {
            self.base58_to_script(address)
        }
    }

    /// Decode a native-segwit (bech32/bech32m) address via the `bech32` crate,
    /// which validates the checksum, variant, witness version, and program
    /// length. Builds `OP_n <push> <program>`.
    fn segwit_to_script(&self, address: &str) -> Result<Vec<u8>, AppError> {
        let (decoded_hrp, witness_version, program) = bech32::segwit::decode(address)
            .map_err(|_| AppError::ValidationError("invalid segwit address".into()))?;
        if decoded_hrp.to_lowercase() != self.network.segwit_hrp() {
            return Err(AppError::ValidationError(
                "address is for a different network".into(),
            ));
        }
        // `segwit::decode` guarantees version 0..=16 and program length 2..=40.
        let version = witness_version.to_u8();
        let mut script = Vec::with_capacity(2 + program.len());
        script.push(if version == 0 { 0x00 } else { 0x50 + version });
        script.push(program.len() as u8);
        script.extend_from_slice(&program);
        Ok(script)
    }

    /// Decode a legacy base58check (P2PKH/P2SH) address, validating the
    /// checksum and the version byte against the configured network.
    fn base58_to_script(&self, address: &str) -> Result<Vec<u8>, AppError> {
        let decoded = bs58::decode(address)
            .into_vec()
            .map_err(|_| AppError::ValidationError("invalid base58 address".into()))?;
        // version(1) + hash160(20) + checksum(4)
        if decoded.len() != 25 {
            return Err(AppError::ValidationError("invalid address length".into()));
        }
        let (payload, checksum) = decoded.split_at(21);
        let first = Sha256::digest(payload);
        let second = Sha256::digest(first);
        if second[..4] != *checksum {
            return Err(AppError::ValidationError("invalid address checksum".into()));
        }

        let version = payload[0];
        let hash160 = &payload[1..]; // exactly 20 bytes
        if version == self.network.p2pkh_version() {
            // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
            let mut s = Vec::with_capacity(25);
            s.extend_from_slice(&[0x76, 0xa9, 0x14]);
            s.extend_from_slice(hash160);
            s.extend_from_slice(&[0x88, 0xac]);
            Ok(s)
        } else if self.network.p2sh_versions().contains(&version) {
            // OP_HASH160 <20> OP_EQUAL
            let mut s = Vec::with_capacity(23);
            s.extend_from_slice(&[0xa9, 0x14]);
            s.extend_from_slice(hash160);
            s.push(0x87);
            Ok(s)
        } else {
            Err(AppError::ValidationError(
                "address is for a different network".into(),
            ))
        }
    }
}

/// Build the shared TLS connector seeded with the webpki root store. Hostname
/// verification is performed by rustls at connect time against the `ServerName`
/// passed in `exchange_ssl`.
fn build_tls_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Parse `ssl://host:port`, `tls://host:port`, or `tcp://host:port`.
fn parse_server_url(url: &str) -> Result<ServerUrl, AppError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| AppError::ConfigError(format!("invalid Electrum server URL: {url}")))?;
    let use_ssl = match scheme {
        "ssl" | "tls" => true,
        "tcp" => false,
        _ => {
            return Err(AppError::ConfigError(format!(
                "unknown scheme '{scheme}' in Electrum URL"
            )))
        }
    };
    let (host, port_str) = rest
        .rsplit_once(':')
        .ok_or_else(|| AppError::ConfigError(format!("missing port in Electrum URL: {url}")))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| AppError::ConfigError(format!("invalid port in Electrum URL: {url}")))?;
    if host.is_empty() {
        return Err(AppError::ConfigError(format!(
            "empty host in Electrum URL: {url}"
        )));
    }
    Ok(ServerUrl {
        host: host.to_string(),
        port,
        use_ssl,
    })
}

/// Map a JSON-RPC envelope to a typed result: surface server errors, reject an
/// id that does not match the request, and require a non-null result.
fn into_result<T>(response: JsonRpcResponse<T>, expected_id: u64) -> Result<T, AppError> {
    let JsonRpcResponse { result, error, id } = response;
    if let Some(err) = error {
        return Err(AppError::NodeError(format!(
            "Electrum RPC error: {}",
            truncate_for_log(&err.message, 200)
        )));
    }
    if id != expected_id {
        return Err(AppError::NodeError("Electrum response id mismatch".into()));
    }
    result.ok_or_else(|| AppError::NodeError("empty Electrum response".into()))
}

/// Write one newline-terminated JSON-RPC request and read one response line,
/// the whole exchange bounded by [`IO_TIMEOUT`] and [`MAX_RESPONSE_BYTES`].
async fn send_request_on_stream<S, T>(
    stream: S,
    method: &str,
    params: &[serde_json::Value],
    id: u64,
) -> Result<JsonRpcResponse<T>, AppError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let exchange = async {
        let (reader, mut writer) = tokio::io::split(stream);

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };
        let mut bytes = serde_json::to_vec(&request)
            .map_err(|_| AppError::NodeError("failed to encode Electrum request".into()))?;
        bytes.push(b'\n');
        writer
            .write_all(&bytes)
            .await
            .map_err(|e| AppError::NodeError(format!("Electrum write failed: {e}")))?;
        writer
            .flush()
            .await
            .map_err(|e| AppError::NodeError(format!("Electrum flush failed: {e}")))?;

        let line = read_response_line(reader, MAX_RESPONSE_BYTES).await?;
        // Parse from the capped buffer; never echo the body into the error.
        serde_json::from_str::<JsonRpcResponse<T>>(&line)
            .map_err(|_| AppError::NodeError("invalid JSON from Electrum server".into()))
    };

    timeout(IO_TIMEOUT, exchange)
        .await
        .map_err(|_| AppError::NodeError("Electrum request timed out".into()))?
}

/// Read a single newline-terminated line, never buffering more than `cap`
/// bytes. A line that reaches the cap without a terminator is rejected as
/// oversized rather than growing memory without bound.
async fn read_response_line<R>(reader: R, cap: u64) -> Result<String, AppError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = BufReader::new(reader.take(cap));
    let mut line = String::new();
    let n = buf
        .read_line(&mut line)
        .await
        .map_err(|e| AppError::NodeError(format!("Electrum read failed: {e}")))?;
    if n == 0 {
        return Err(AppError::NodeError(
            "Electrum connection closed before response".into(),
        ));
    }
    if !line.ends_with('\n') && line.len() as u64 >= cap {
        return Err(AppError::NodeError(
            "Electrum response exceeded size limit".into(),
        ));
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> UtxoConfig {
        UtxoConfig {
            network: "mainnet".into(),
            electrum_primary: None,
            electrum_fallbacks: vec![],
        }
    }

    fn btc() -> ElectrumClient {
        ElectrumClient::new(UtxoNetwork::BitcoinMainnet, &cfg()).unwrap()
    }

    fn ltc() -> ElectrumClient {
        ElectrumClient::new(UtxoNetwork::LitecoinMainnet, &cfg()).unwrap()
    }

    fn spk(addr: &str) -> ScriptPubKeyInfo {
        ScriptPubKeyInfo {
            address: Some(addr.to_string()),
            addresses: None,
        }
    }

    // --- server URL parsing ---

    #[test]
    fn parse_server_url_variants() {
        let ssl = parse_server_url("ssl://electrum.example:50002").unwrap();
        assert_eq!(ssl.host, "electrum.example");
        assert_eq!(ssl.port, 50002);
        assert!(ssl.use_ssl);

        let tcp = parse_server_url("tcp://localhost:50001").unwrap();
        assert!(!tcp.use_ssl);
        assert_eq!(tcp.port, 50001);

        assert!(parse_server_url("electrum.example:50002").is_err()); // no scheme
        assert!(parse_server_url("http://electrum.example:50002").is_err()); // bad scheme
        assert!(parse_server_url("ssl://electrum.example").is_err()); // no port
        assert!(parse_server_url("ssl://electrum.example:notaport").is_err());
        assert!(parse_server_url("ssl://:50002").is_err()); // empty host
    }

    // --- address -> scriptPubKey KATs (the scripthash-determining step) ---

    #[test]
    fn bech32_p2wpkh_script_kat() {
        // BIP173 canonical example.
        let script = btc()
            .address_to_script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            .unwrap();
        assert_eq!(
            script,
            hex::decode("0014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap()
        );
    }

    #[test]
    fn bech32_p2wsh_script_kat() {
        // BIP173 canonical P2WSH example.
        let script = btc()
            .address_to_script("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
            .unwrap();
        assert_eq!(
            script,
            hex::decode("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
                .unwrap()
        );
    }

    #[test]
    fn bech32m_v1_taproot_roundtrip() {
        // Generate a guaranteed-valid v1 (bech32m) address from a 32-byte
        // program with the same crate, then prove our decoder rebuilds the
        // canonical taproot script `OP_1 <0x20> <program>`.
        let program = [0x42u8; 32];
        let hrp = bech32::Hrp::parse("bc").unwrap();
        let addr = bech32::segwit::encode_v1(hrp, &program).unwrap();

        let script = btc().address_to_script(&addr).unwrap();
        assert_eq!(script.len(), 34);
        assert_eq!(script[0], 0x51); // OP_1 (witness v1)
        assert_eq!(script[1], 0x20); // push 32
        assert_eq!(&script[2..], &program);
    }

    #[test]
    fn legacy_p2pkh_script_structure() {
        // Bitcoin genesis P2PKH address. Verify our P2PKH construction wraps
        // exactly the embedded hash160 (computed here from base58, so the test
        // pins our script shape, not a memorized hash).
        let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let script = btc().address_to_script(addr).unwrap();
        let decoded = bs58::decode(addr).into_vec().unwrap();
        let hash160 = &decoded[1..21];

        let mut expected = vec![0x76, 0xa9, 0x14];
        expected.extend_from_slice(hash160);
        expected.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(script, expected);
    }

    #[test]
    fn legacy_p2sh_script_structure() {
        // A well-known Bitcoin P2SH ("3...") address.
        let addr = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
        let script = btc().address_to_script(addr).unwrap();
        let decoded = bs58::decode(addr).into_vec().unwrap();
        let hash160 = &decoded[1..21];

        let mut expected = vec![0xa9, 0x14];
        expected.extend_from_slice(hash160);
        expected.push(0x87);
        assert_eq!(script, expected);
    }

    #[test]
    fn scripthash_is_reversed_sha256_hex() {
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let client = btc();
        let script = client.address_to_script(addr).unwrap();
        let sh = client.address_to_scripthash(addr).unwrap();

        let mut expected: Vec<u8> = Sha256::digest(&script).to_vec();
        expected.reverse();
        assert_eq!(sh, hex::encode(expected));
        assert_eq!(sh.len(), 64);
    }

    // --- network enforcement ---

    #[test]
    fn rejects_foreign_network_address() {
        // A valid Bitcoin mainnet P2PKH must be rejected by a Litecoin client
        // (version byte 0x00 is neither LTC P2PKH nor P2SH).
        let err = ltc()
            .address_to_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
            .unwrap_err();
        assert!(matches!(err, AppError::ValidationError(_)), "{err:?}");

        // A Bitcoin native-segwit address must be rejected by a Litecoin client.
        assert!(ltc()
            .address_to_script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            .is_err());
    }

    // --- panic-safety regression: short/garbage addresses must Err, not panic ---

    #[test]
    fn short_and_garbage_addresses_do_not_panic() {
        for bad in [
            "", "1", "bc", "bc1", "bc11", "bc1q", "bc1qqqqq", "ßßß", "tb1!", "ltc1",
        ] {
            assert!(
                btc().address_to_script(bad).is_err(),
                "expected Err for {bad:?}"
            );
        }
    }

    // --- checked f64 -> sat conversion (money-corruption defense) ---

    #[test]
    fn checked_btc_to_sat_accepts_valid() {
        assert_eq!(checked_btc_to_sat(0.0).unwrap(), 0);
        assert_eq!(checked_btc_to_sat(0.00000001).unwrap(), 1);
        assert_eq!(checked_btc_to_sat(1.0).unwrap(), 100_000_000);
        // 21M BTC (the Bitcoin supply cap) is well under the 2^53 ceiling.
        assert_eq!(
            checked_btc_to_sat(21_000_000.0).unwrap(),
            2_100_000_000_000_000
        );
    }

    #[test]
    fn checked_btc_to_sat_rejects_hostile() {
        assert!(checked_btc_to_sat(f64::NAN).is_err());
        assert!(checked_btc_to_sat(f64::INFINITY).is_err());
        assert!(checked_btc_to_sat(f64::NEG_INFINITY).is_err());
        assert!(checked_btc_to_sat(-1.0).is_err());
        assert!(checked_btc_to_sat(-0.00000001).is_err());
        // ~1e9 BTC -> 1e17 sat, beyond the 2^53 exact-integer ceiling.
        assert!(checked_btc_to_sat(1_000_000_000.0).is_err());
    }

    // --- verbose tx attribution (received exact; sent exact-or-decline) ---

    fn tx_with_change_no_prevout() -> VerboseTransaction {
        // Recipient receives 0.001; sender's 0.296 change returns to the sender.
        // Inputs carry only the prevout reference (public-ElectrumX shape).
        VerboseTransaction {
            txid: "fund".into(),
            vin: vec![VerboseVin {
                txid: Some("prev".into()),
                vout: Some(0),
                prevout: None,
            }],
            vout: vec![
                VerboseVout {
                    value: 0.001,
                    n: 0,
                    script_pub_key: spk("addr_recipient"),
                },
                VerboseVout {
                    value: 0.296,
                    n: 1,
                    script_pub_key: spk("addr_sender"),
                },
            ],
        }
    }

    #[test]
    fn total_received_at_is_exact() {
        let tx = tx_with_change_no_prevout();
        assert_eq!(tx.total_received_at("addr_recipient").unwrap(), 100_000);
        assert_eq!(tx.total_received_at("addr_sender").unwrap(), 29_600_000);
        assert_eq!(tx.total_received_at("addr_unrelated").unwrap(), 0);
    }

    #[test]
    fn total_sent_declines_without_prevout() {
        // The old heuristic wrongly reported the whole tx output as "sent from"
        // the recipient. The clean client declines (None) instead of guessing.
        let tx = tx_with_change_no_prevout();
        assert_eq!(tx.total_sent_from("addr_recipient").unwrap(), None);
    }

    #[test]
    fn total_sent_is_exact_with_prevout() {
        // Fulcrum-class server resolves prevouts: sent is computed exactly.
        let tx = VerboseTransaction {
            txid: "spend".into(),
            vin: vec![VerboseVin {
                txid: Some("prev".into()),
                vout: Some(0),
                prevout: Some(Prevout {
                    value: 0.5,
                    script_pub_key: spk("addr_sender"),
                }),
            }],
            vout: vec![VerboseVout {
                value: 0.4999,
                n: 0,
                script_pub_key: spk("addr_dest"),
            }],
        };
        assert_eq!(tx.total_sent_from("addr_sender").unwrap(), Some(50_000_000));
        assert_eq!(tx.total_sent_from("addr_dest").unwrap(), Some(0));
    }

    #[test]
    fn total_sent_declines_on_partial_prevouts() {
        // A mixed response — one input resolved, one not, both ours — must NOT
        // return Some (which would silently omit the unresolved input's value);
        // `Some` is reserved for fully-resolved, exact answers.
        let tx = VerboseTransaction {
            txid: "mixed".into(),
            vin: vec![
                VerboseVin {
                    txid: Some("a".into()),
                    vout: Some(0),
                    prevout: Some(Prevout {
                        value: 1.0,
                        script_pub_key: spk("addr_sender"),
                    }),
                },
                VerboseVin {
                    txid: Some("b".into()),
                    vout: Some(1),
                    prevout: None,
                },
            ],
            vout: vec![VerboseVout {
                value: 1.4999,
                n: 0,
                script_pub_key: spk("addr_dest"),
            }],
        };
        assert_eq!(tx.total_sent_from("addr_sender").unwrap(), None);
    }

    #[test]
    fn verbose_tx_rejects_hostile_amount() {
        // A non-finite amount must surface as an error, not a silent 0/u64::MAX.
        let tx = VerboseTransaction {
            txid: "evil".into(),
            vin: vec![],
            vout: vec![VerboseVout {
                value: f64::INFINITY,
                n: 0,
                script_pub_key: spk("addr"),
            }],
        };
        assert!(tx.total_received_at("addr").is_err());
    }

    // --- JSON-RPC envelope mapping ---

    #[test]
    fn into_result_maps_envelope() {
        // Happy path: matching id, present result.
        let ok = JsonRpcResponse::<u64> {
            result: Some(42),
            error: None,
            id: 7,
        };
        assert_eq!(into_result(ok, 7).unwrap(), 42);

        // Id mismatch is rejected (response-correlation guard).
        let mism = JsonRpcResponse::<u64> {
            result: Some(42),
            error: None,
            id: 9,
        };
        assert!(into_result(mism, 7).is_err());

        // Server error surfaces; control chars in the message are stripped.
        let errd = JsonRpcResponse::<u64> {
            result: None,
            error: Some(JsonRpcError {
                message: "bad\nrequest".into(),
            }),
            id: 7,
        };
        let e = into_result(errd, 7).unwrap_err();
        match e {
            AppError::NodeError(m) => assert!(!m.contains('\n'), "control char leaked: {m:?}"),
            other => panic!("expected NodeError, got {other:?}"),
        }

        // Null result with matching id is an error.
        let empty = JsonRpcResponse::<u64> {
            result: None,
            error: None,
            id: 7,
        };
        assert!(into_result(empty, 7).is_err());
    }

    // --- bounded read ---

    #[tokio::test]
    async fn read_response_line_reads_one_line() {
        let data: &[u8] = b"{\"id\":1,\"result\":true}\nextra-ignored";
        let line = read_response_line(data, MAX_RESPONSE_BYTES).await.unwrap();
        assert_eq!(line, "{\"id\":1,\"result\":true}\n");
    }

    #[tokio::test]
    async fn read_response_line_rejects_oversized() {
        // A line that reaches the cap without a newline is rejected, not buffered.
        let data = [b'a'; 128];
        let err = read_response_line(&data[..], 64).await.unwrap_err();
        assert!(matches!(err, AppError::NodeError(_)), "{err:?}");
    }

    #[tokio::test]
    async fn read_response_line_rejects_empty_stream() {
        let data: &[u8] = b"";
        assert!(read_response_line(data, 64).await.is_err());
    }

    // --- full wire exchange over an in-memory duplex (id correlation) ---

    #[tokio::test]
    async fn send_request_round_trip_correlates_id() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let (r, mut w) = tokio::io::split(server_io);
            let mut br = BufReader::new(r);
            let mut req = String::new();
            br.read_line(&mut req).await.unwrap();
            let v: serde_json::Value = serde_json::from_str(&req).unwrap();
            let id = v["id"].as_u64().unwrap();
            assert_eq!(v["method"], "blockchain.scripthash.get_balance");
            let resp =
                format!("{{\"id\":{id},\"result\":{{\"confirmed\":42,\"unconfirmed\":-3}}}}\n");
            w.write_all(resp.as_bytes()).await.unwrap();
        });

        let params = vec![serde_json::json!("deadbeef")];
        let resp: JsonRpcResponse<ElectrumBalance> =
            send_request_on_stream(client_io, "blockchain.scripthash.get_balance", &params, 7)
                .await
                .unwrap();
        server.await.unwrap();

        let balance = into_result(resp, 7).unwrap();
        assert_eq!(balance.confirmed, 42);
        assert_eq!(balance.unconfirmed, -3);
    }
}
