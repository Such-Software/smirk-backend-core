//! LWS (light-wallet-server) client for Monero/Wownero.
//!
//! The backend runs no Monero/Wownero wallet — an LWS scans the chain for
//! registered view keys and answers balance/history/output/broadcast queries.
//! Wownero is a Monero fork with an identical LWS API, so one generic client
//! serves both, keyed by [`CryptoNoteNetwork`].
//!
//! Every response is treated as hostile (the LWS may be remote/community-run):
//!
//!   * a single shared `reqwest::Client` with request + connect timeouts;
//!   * each response body is read through a **streaming size cap** and parsed
//!     with `serde_json::from_slice` — no byte-indexing of an untrusted body
//!     (the old `&text[..2000]` / error-column slices are gone);
//!   * non-success responses map to a generic [`AppError::NodeError`] tagged
//!     with a static endpoint label + status — the response body is never
//!     interpolated into a log or error;
//!   * the admin key is held in a redacting [`Secret`] and skipped in tracing;
//!   * the decoy/ring count and request fan-out are clamped/capped.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;
use tracing::instrument;

use super::types::*;
use crate::config::LwsConfig;
use crate::core::secret::Secret;
use crate::error::AppError;

/// Per-request deadline.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// TCP connect deadline.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard cap on any LWS/daemon response body (enforced while streaming).
const MAX_LWS_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Defensive ceiling on the per-output decoy count (the protocol ring is ~16).
const MAX_DECOY_COUNT: u32 = 64;
/// Ceiling on amounts requested in one `get_random_outs` call, and on parsed
/// fan-out Vecs — defends against a hostile server inflating compute/memory
/// (the body cap is the primary bound; these are belt-and-suspenders).
const MAX_PARSED_VEC: usize = 100_000;

/// Generic LWS client for a Monero-family network.
#[derive(Clone)]
pub struct LwsClient {
    network: CryptoNoteNetwork,
    user_url: String,
    admin_url: String,
    admin_key: Secret,
    daemon_url: String,
    http: reqwest::Client,
}

impl LwsClient {
    /// Build a Monero LWS client from its config.
    pub fn monero(cfg: &LwsConfig) -> Result<Self, AppError> {
        Self::new(CryptoNoteNetwork::Monero, cfg)
    }

    /// Build a Wownero LWS client from its config.
    pub fn wownero(cfg: &LwsConfig) -> Result<Self, AppError> {
        Self::new(CryptoNoteNetwork::Wownero, cfg)
    }

    /// Construct a client with a shared timeout-bounded HTTP client.
    pub fn new(network: CryptoNoteNetwork, cfg: &LwsConfig) -> Result<Self, AppError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|_| AppError::NodeError("failed to build LWS HTTP client".into()))?;
        Ok(Self {
            network,
            user_url: cfg.lws_url.clone(),
            admin_url: cfg.lws_admin_url.clone(),
            admin_key: Secret::new(cfg.lws_admin_key.clone()),
            daemon_url: cfg.daemon_url.clone(),
            http,
        })
    }

    /// The network this client serves.
    pub fn network(&self) -> CryptoNoteNetwork {
        self.network
    }

    // ── user API ────────────────────────────────────────────────────────────

    /// Address info (balance + scan state).
    #[instrument(skip(self, view_key), fields(net = %self.network))]
    pub async fn get_address_info(
        &self,
        address: &str,
        view_key: &str,
    ) -> Result<AddressInfo, AppError> {
        let url = format!("{}/get_address_info", self.user_url);
        let body = GetAddressInfoRequest {
            address: address.to_string(),
            view_key: view_key.to_string(),
        };
        self.post_json(url, "get_address_info", &body).await
    }

    /// Balance (received) in atomic units.
    pub async fn get_balance(&self, address: &str, view_key: &str) -> Result<u64, AppError> {
        Ok(self.get_address_info(address, view_key).await?.balance())
    }

    /// Unlocked (spendable) balance in atomic units.
    pub async fn get_unlocked_balance(
        &self,
        address: &str,
        view_key: &str,
    ) -> Result<u64, AppError> {
        Ok(self
            .get_address_info(address, view_key)
            .await?
            .unlocked_balance())
    }

    /// Transaction history (confirmed + mempool).
    #[instrument(skip(self, view_key), fields(net = %self.network))]
    pub async fn get_address_txs(
        &self,
        address: &str,
        view_key: &str,
    ) -> Result<AddressTxsResponse, AppError> {
        let url = format!("{}/get_address_txs", self.user_url);
        let body = GetAddressTxsRequest {
            address: address.to_string(),
            view_key: view_key.to_string(),
        };
        let resp: AddressTxsResponse = self.post_json(url, "get_address_txs", &body).await?;
        if resp.transactions.len() > MAX_PARSED_VEC {
            return Err(self.node_err("get_address_txs", "response too large"));
        }
        Ok(resp)
    }

    /// Sum of unconfirmed (mempool) received amounts — the "pending" balance.
    pub async fn get_mempool_balance(
        &self,
        address: &str,
        view_key: &str,
    ) -> Result<u64, AppError> {
        let txs = self.get_address_txs(address, view_key).await?;
        Ok(sum_mempool_received(&txs.transactions))
    }

    /// Unspent outputs for transaction construction.
    #[instrument(skip(self, view_key), fields(net = %self.network))]
    pub async fn get_unspent_outs(
        &self,
        address: &str,
        view_key: &str,
    ) -> Result<UnspentOutsResponse, AppError> {
        let url = format!("{}/get_unspent_outs", self.user_url);
        let body = GetUnspentOutsRequest {
            address: address.to_string(),
            view_key: view_key.to_string(),
            amount: "0".to_string(), // all
            mixin: None,
            use_dust: true,
            dust_threshold: "0".to_string(),
        };
        let resp: UnspentOutsResponse = self.post_json(url, "get_unspent_outs", &body).await?;
        if resp.outputs.len() > MAX_PARSED_VEC {
            return Err(self.node_err("get_unspent_outs", "response too large"));
        }
        Ok(resp)
    }

    /// Random decoy outputs for ring selection. `count` is the per-output decoy
    /// count (protocol-fixed, ~16); it is clamped and the amount list is bounded
    /// so a hostile/buggy caller or server cannot inflate the fan-out.
    #[instrument(skip(self), fields(net = %self.network))]
    pub async fn get_random_outs(
        &self,
        count: u32,
        amounts: Vec<String>,
    ) -> Result<RandomOutsResponse, AppError> {
        if amounts.len() > MAX_PARSED_VEC {
            return Err(AppError::ValidationError(
                "too many amounts requested".into(),
            ));
        }
        let count = count.min(MAX_DECOY_COUNT);
        let url = format!("{}/get_random_outs", self.user_url);
        let body = GetRandomOutsRequest { count, amounts };
        let resp: RandomOutsResponse = self.post_json(url, "get_random_outs", &body).await?;
        if resp.amount_outs.len() > MAX_PARSED_VEC {
            return Err(self.node_err("get_random_outs", "response too large"));
        }
        Ok(resp)
    }

    /// Broadcast a signed raw transaction.
    #[instrument(skip(self, tx_hex), fields(net = %self.network))]
    pub async fn submit_raw_tx(&self, tx_hex: &str) -> Result<(), AppError> {
        let url = format!("{}/submit_raw_tx", self.user_url);
        let body = SubmitRawTxRequest {
            tx: tx_hex.to_string(),
        };
        self.post_ok(url, "submit_raw_tx", &body).await
    }

    // ── admin API ────────────────────────────────────────────────────────────

    /// Register + activate an account (admin `add_account`), scanning from the
    /// current height.
    #[instrument(skip(self, view_key), fields(net = %self.network))]
    pub async fn register_account(&self, address: &str, view_key: &str) -> Result<(), AppError> {
        self.admin_add_account(address, view_key, None).await
    }

    /// Register + activate an account scanning from a specific `start_height`
    /// (avoids re-scanning from genesis for an older wallet).
    #[instrument(skip(self, view_key), fields(net = %self.network))]
    pub async fn import_account(
        &self,
        address: &str,
        view_key: &str,
        start_height: u64,
    ) -> Result<(), AppError> {
        self.admin_add_account(address, view_key, Some(start_height))
            .await
    }

    async fn admin_add_account(
        &self,
        address: &str,
        view_key: &str,
        start_height: Option<u64>,
    ) -> Result<(), AppError> {
        let url = format!("{}/add_account", self.admin_url);
        let body = AdminAddAccountRequest {
            auth: self.admin_key.expose().to_string(),
            params: AdminAddAccountParams {
                address: address.to_string(),
                key: view_key.to_string(),
                start_height,
            },
        };
        self.post_ok(url, "add_account", &body).await
    }

    /// List all registered accounts (active / inactive / hidden).
    #[instrument(skip(self), fields(net = %self.network))]
    pub async fn list_accounts(&self) -> Result<ListAccountsResponse, AppError> {
        let url = format!("{}/list_accounts", self.admin_url);
        let body = ListAccountsBody {
            auth: self.admin_key.expose().to_string(),
        };
        self.post_json(url, "list_accounts", &body).await
    }

    /// Current `scan_height` for `address`, or `None` if the LWS doesn't know it.
    ///
    /// Filters `list_accounts` client-side; fine at small account counts. If the
    /// account set grows large, switch to a per-account query.
    pub async fn account_scan_height(&self, address: &str) -> Result<Option<u64>, AppError> {
        let accounts = self.list_accounts().await?;
        for bucket in [&accounts.active, &accounts.inactive, &accounts.hidden] {
            if let Some(entry) = bucket.iter().find(|e| e.address == address) {
                return Ok(Some(entry.scan_height));
            }
        }
        Ok(None)
    }

    /// Set the scan status of accounts (active / inactive / hidden).
    #[instrument(skip(self), fields(net = %self.network, status = ?status))]
    pub async fn modify_account_status(
        &self,
        addresses: Vec<String>,
        status: AccountStatus,
    ) -> Result<(), AppError> {
        if addresses.is_empty() {
            return Ok(());
        }
        let url = format!("{}/modify_account_status", self.admin_url);
        let body = ModifyAccountStatusRequest {
            auth: self.admin_key.expose().to_string(),
            params: ModifyAccountStatusParams { addresses, status },
        };
        self.post_ok(url, "modify_account_status", &body).await
    }

    /// Tell the LWS to rescan `addresses` from `height`.
    ///
    /// **SAFETY: backwards-only.** monero-lws resets `scan_height` to `height`
    /// and re-scans forward. `height >= current scan_height` is undefined
    /// behavior (can leave the account inactive or corrupt LMDB state). Callers
    /// MUST read the current `scan_height` first and only invoke when strictly
    /// lowering it.
    #[instrument(skip(self), fields(net = %self.network, height, n = addresses.len()))]
    pub async fn rescan(&self, addresses: Vec<String>, height: u64) -> Result<(), AppError> {
        if addresses.is_empty() {
            return Ok(());
        }
        let url = format!("{}/rescan", self.admin_url);
        let body = RescanRequest {
            auth: self.admin_key.expose().to_string(),
            params: RescanParams { addresses, height },
        };
        self.post_ok(url, "rescan", &body).await
    }

    // ── daemon API (direct node queries) ──────────────────────────────────────

    /// Current chain height from the daemon (`get_info`).
    #[instrument(skip(self), fields(net = %self.network))]
    pub async fn get_blockchain_height(&self) -> Result<u64, AppError> {
        if self.daemon_url.is_empty() {
            return Err(self.node_err("daemon", "daemon URL not configured"));
        }

        #[derive(Serialize)]
        struct Req {
            jsonrpc: &'static str,
            id: &'static str,
            method: &'static str,
        }
        #[derive(Deserialize)]
        struct Resp {
            result: Option<GetInfo>,
            #[serde(default)]
            error: Option<serde_json::Value>,
        }
        #[derive(Deserialize)]
        struct GetInfo {
            height: u64,
        }

        let url = format!("{}/json_rpc", self.daemon_url);
        let body = Req {
            jsonrpc: "2.0",
            id: "0",
            method: "get_info",
        };
        let resp: Resp = self.post_json(url, "daemon get_info", &body).await?;
        if resp.error.is_some() {
            return Err(self.node_err("daemon get_info", "daemon returned an error"));
        }
        resp.result
            .map(|r| r.height)
            .ok_or_else(|| self.node_err("daemon get_info", "no result"))
    }

    /// Confirmation count for `txid`, or `None` if not found / still in mempool
    /// without a height. Queries the daemon's `/get_transactions`.
    #[instrument(skip(self), fields(net = %self.network))]
    pub async fn get_transaction_confirmations(&self, txid: &str) -> Result<Option<u64>, AppError> {
        if self.daemon_url.is_empty() {
            return Err(self.node_err("daemon", "daemon URL not configured"));
        }
        let current_height = self.get_blockchain_height().await?;

        #[derive(Serialize)]
        struct Req {
            txs_hashes: Vec<String>,
        }
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            txs: Option<Vec<TxInfo>>,
            #[serde(default)]
            status: String,
        }
        #[derive(Deserialize)]
        struct TxInfo {
            block_height: Option<u64>,
            in_pool: Option<bool>,
        }

        let url = format!("{}/get_transactions", self.daemon_url);
        let body = Req {
            txs_hashes: vec![txid.to_string()],
        };
        let resp: Resp = self
            .post_json(url, "daemon get_transactions", &body)
            .await?;
        if resp.status != "OK" {
            return Ok(None);
        }
        let Some(tx) = resp.txs.and_then(|txs| txs.into_iter().next()) else {
            return Ok(None);
        };
        Ok(confirmations_from(
            tx.block_height,
            tx.in_pool,
            current_height,
        ))
    }

    /// Liveness probe — reaches the admin API.
    pub async fn health_check(&self) -> Result<(), AppError> {
        self.list_accounts().await?;
        Ok(())
    }

    // ── internal HTTP helpers ─────────────────────────────────────────────────

    /// POST a JSON body and deserialize a successful response from a size-capped
    /// buffer. Non-success → generic `NodeError` (no body interpolation).
    async fn post_json<B, R>(
        &self,
        url: String,
        label: &'static str,
        body: &B,
    ) -> Result<R, AppError>
    where
        B: Serialize,
        R: DeserializeOwned,
    {
        let resp = self.http.post(&url).json(body).send().await.map_err(|e| {
            // Transport-level failure (connect/DNS/timeout) — not a response
            // body. Safe to log privately; redacted from the client response.
            AppError::NodeError(format!("{} LWS {label} request failed: {e}", self.network))
        })?;
        if !resp.status().is_success() {
            return Err(self.node_err_status(label, resp.status()));
        }
        let bytes = read_capped(resp, MAX_LWS_BODY_BYTES).await?;
        serde_json::from_slice::<R>(&bytes).map_err(|_| self.node_err(label, "invalid response"))
    }

    /// POST a JSON body where only success/failure matters (no response body).
    async fn post_ok<B: Serialize>(
        &self,
        url: String,
        label: &'static str,
        body: &B,
    ) -> Result<(), AppError> {
        let resp = self.http.post(&url).json(body).send().await.map_err(|e| {
            // Transport-level failure (connect/DNS/timeout) — not a response
            // body. Safe to log privately; redacted from the client response.
            AppError::NodeError(format!("{} LWS {label} request failed: {e}", self.network))
        })?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(self.node_err_status(label, resp.status()))
        }
    }

    /// A network-tagged node error. `label`/`detail` are static; the untrusted
    /// response body is never included.
    fn node_err(&self, label: &str, detail: &str) -> AppError {
        AppError::NodeError(format!("{} LWS {label}: {detail}", self.network))
    }

    fn node_err_status(&self, label: &str, status: reqwest::StatusCode) -> AppError {
        AppError::NodeError(format!(
            "{} LWS {label} failed (HTTP {})",
            self.network,
            status.as_u16()
        ))
    }
}

/// Sum the mempool (unconfirmed) net-received amounts, saturating at each step
/// so a hostile per-tx value cannot overflow-panic the total.
fn sum_mempool_received(txs: &[AddressTx]) -> u64 {
    txs.iter()
        .filter(|t| t.mempool)
        .map(|t| t.total_received.saturating_sub(t.total_sent))
        .fold(0u64, |acc, v| acc.saturating_add(v))
}

/// Confirmation count for a tx given the daemon's view of it. `None` = not
/// found / no height yet; `Some(0)` = in the mempool, or an *inconsistent*
/// block claim (a height beyond our reported tip — a lagging or lying daemon),
/// which is treated as not-yet-confirmed rather than a bogus `1`.
fn confirmations_from(
    block_height: Option<u64>,
    in_pool: Option<bool>,
    current_height: u64,
) -> Option<u64> {
    if in_pool == Some(true) {
        return Some(0);
    }
    match block_height {
        Some(h) if h > current_height => Some(0),
        Some(h) => Some(current_height.saturating_sub(h).saturating_add(1)),
        None => None,
    }
}

/// Read a response body into memory, enforcing `cap` as bytes arrive (the
/// content-length header is attacker-asserted, so it is not trusted).
async fn read_capped(resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, AppError> {
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError::NodeError("LWS read failed".into()))?;
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(AppError::NodeError(
                "LWS response exceeded size limit".into(),
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LwsConfig {
        LwsConfig {
            lws_url: "http://127.0.0.1:8443".into(),
            lws_admin_url: "http://127.0.0.1:9443".into(),
            lws_admin_key: "test-admin-key".into(),
            daemon_url: String::new(),
        }
    }

    #[test]
    fn constructors_set_network() {
        assert_eq!(
            LwsClient::monero(&cfg()).unwrap().network(),
            CryptoNoteNetwork::Monero
        );
        assert_eq!(
            LwsClient::wownero(&cfg()).unwrap().network(),
            CryptoNoteNetwork::Wownero
        );
    }

    #[test]
    fn admin_key_is_redacted_in_debug() {
        let client = LwsClient::monero(&cfg()).unwrap();
        // The Secret wrapper must hide the key even if the field is formatted.
        assert_eq!(format!("{:?}", client.admin_key), "Secret(***)");
        assert!(!format!("{:?}", client.admin_key).contains("test-admin-key"));
    }

    fn tx(mempool: bool, received: u64, sent: u64) -> AddressTx {
        AddressTx {
            hash: "h".into(),
            height: 0,
            timestamp: String::new(),
            total_received: received,
            total_sent: sent,
            mempool,
            unlock_time: 0,
            payment_id: None,
            spent_outputs: vec![],
        }
    }

    #[test]
    fn mempool_sum_counts_only_mempool_and_saturates() {
        let txs = vec![
            tx(true, 1000, 200),   // net 800 (mempool)
            tx(false, 9999, 0),    // confirmed — excluded
            tx(true, 50, 100),     // net 0 via saturating_sub (sent > received)
            tx(true, u64::MAX, 0), // huge — total saturates, never panics
        ];
        assert_eq!(sum_mempool_received(&txs), u64::MAX);

        let modest = vec![tx(true, 1000, 200), tx(true, 500, 0), tx(false, 1, 0)];
        assert_eq!(sum_mempool_received(&modest), 1300);
    }

    #[tokio::test]
    async fn get_random_outs_rejects_too_many_amounts() {
        let client = LwsClient::monero(&cfg()).unwrap();
        // The amount-count guard fires before any network call.
        let amounts = vec!["0".to_string(); MAX_PARSED_VEC + 1];
        let err = client.get_random_outs(11, amounts).await.unwrap_err();
        assert!(matches!(err, AppError::ValidationError(_)), "{err:?}");
    }

    #[test]
    fn confirmations_math_handles_mempool_tip_and_future() {
        // Mempool → 0 confirmations.
        assert_eq!(confirmations_from(None, Some(true), 110), Some(0));
        // In a past block: current - height + 1.
        assert_eq!(confirmations_from(Some(100), Some(false), 110), Some(11));
        // In the tip block: exactly 1.
        assert_eq!(confirmations_from(Some(110), None, 110), Some(1));
        // A block beyond our tip (lagging/lying daemon) → 0, not a bogus 1.
        assert_eq!(confirmations_from(Some(120), Some(false), 110), Some(0));
        // Confirmed flag absent and no height → unknown.
        assert_eq!(confirmations_from(None, None, 110), None);
    }

    #[tokio::test]
    async fn daemon_height_requires_daemon_url() {
        let client = LwsClient::monero(&cfg()).unwrap(); // daemon_url empty
        let err = client.get_blockchain_height().await.unwrap_err();
        assert!(matches!(err, AppError::NodeError(_)), "{err:?}");
    }
}
