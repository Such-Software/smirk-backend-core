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
    /// First-use probe of the LWS `--max-subaddresses` option, cached for the
    /// process. Shared across clones (an `AppState` hands out `LwsClient`
    /// clones), so the probe runs once per network, not once per request. A
    /// FAILED probe is not cached, so a temporarily unreachable LWS is retried.
    subaddr_capacity: std::sync::Arc<tokio::sync::OnceCell<u32>>,
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
            subaddr_capacity: std::sync::Arc::default(),
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
    /// current height, then provision `provision_minors` subaddress indices for
    /// account 0 (`0` = provisioning disabled — the dark default).
    ///
    /// Provisioning runs AFTER the add so the account exists first. A provision
    /// failure is a HARD error (money gate G3: never silently skip — a wallet
    /// that expects subaddress receipts must not be told scanning is set up when
    /// the subaddresses were not registered).
    #[instrument(skip(self, view_key), fields(net = %self.network, provision_minors))]
    pub async fn register_account(
        &self,
        address: &str,
        view_key: &str,
        provision_minors: u32,
    ) -> Result<(), AppError> {
        if provision_minors == 0 {
            // Provisioning off (the dark default): exactly the call this made
            // before, including monero-lws answering a duplicate `add_account`
            // with `account_exists` (an HTTP 500 it maps to a node error).
            return self.admin_add_account(address, view_key).await;
        }
        // Provisioning on: an account that ALREADY exists must still be brought
        // up to the required ceiling. monero-lws fails a duplicate `add_account`
        // (`db::storage::do_add_account` returns `lws::error::account_exists`,
        // served as a 500), so calling it unconditionally would abort before the
        // provisioning below and make the account permanently unprovisionable
        // through this path. Existence is checked first instead; nothing about
        // the account's scan state is touched.
        if self.account_scan_height(address).await?.is_none() {
            self.admin_add_account(address, view_key).await?;
        }
        self.provision_account0_covering(address, view_key, provision_minors)
            .await?;
        Ok(())
    }

    /// The LWS `--max-subaddresses` ceiling, probed once and cached.
    ///
    /// monero-lws exposes it on the USER endpoint `/get_version`
    /// (`rest_server.cpp` `endpoints[]`, `is_admin = false`), and rejects any
    /// `provision_subaddrs` whose `n_maj * n_min` exceeds it. It defaults to `0`
    /// (subaddresses DISABLED), which is exactly the misconfiguration that made
    /// provisioning fail late and half-way.
    pub async fn max_subaddresses(&self) -> Result<u32, AppError> {
        let cached = self
            .subaddr_capacity
            .get_or_try_init(|| async {
                let url = format!("{}/get_version", self.user_url);
                let resp: LwsVersionResponse = self
                    .post_json(url, "get_version", &serde_json::json!({}))
                    .await?;
                Ok::<u32, AppError>(resp.max_subaddresses)
            })
            .await?;
        Ok(*cached)
    }

    /// Fail CLOSED unless this LWS can satisfy a `n_min`-wide provision for one
    /// major index: refuse up front with an operator-legible error rather than
    /// registering an account that only half-works (scanning set up, subaddress
    /// receipts silently unattributed).
    async fn ensure_subaddr_capacity(&self, n_min: u32) -> Result<(), AppError> {
        let max = self.max_subaddresses().await?;
        if max < n_min {
            return Err(AppError::NodeError(format!(
                "{} LWS cannot provision subaddresses: it allows max_subaddresses={max} \
                 but {n_min} are required. Start monero-lws with \
                 --max-subaddresses {n_min} (or higher), or disable \
                 FEATURE_XMR_SUBADDR_PROVISIONING.",
                self.network
            )));
        }
        Ok(())
    }

    /// Provision (`upsert`) subaddress ranges at the LWS so it attributes
    /// subaddress receipts, via the USER endpoint `/provision_subaddrs`.
    ///
    /// CONFIRMED a USER endpoint (keyed by `address` + `view_key`, NOT admin):
    /// monero-lws registers `/provision_subaddrs` in `src/rest_server.cpp`
    /// `endpoints[]` with `is_admin = false`, and its wire reader
    /// (`src/rpc/light_wallet.cpp` `read_bytes(provision_subaddrs_request&)`)
    /// reads `address` + `view_key` + optional `maj_i/min_i/n_maj/n_min/get_all`.
    ///
    /// Provisions the `[min_i .. min_i + n_min)` minor range for ONE major index
    /// (`maj_i`; `n_maj = 1`). SAFETY/LIVE-GATE: the LWS must be started with
    /// `--max-subaddresses >= n_min` — it defaults to `0` (subaddresses
    /// DISABLED), in which case the LWS returns a `max_subaddresses` error.
    /// Returns the CONFIRMED contiguous minor ceiling for `maj_i` as the LWS
    /// reports it back, never the ask. `get_all` is sent as `true` because
    /// `new_subaddrs` carries only the ranges a call newly added (an idempotent
    /// repeat returns it empty), so `all_subaddrs` is the only field that can
    /// state the ceiling actually in force. A body from which the ceiling cannot
    /// be established is an ERROR, never a guess: a ceiling the wallet trusts
    /// but the LWS is not scanning turns a receive into invisible funds.
    #[instrument(skip(self, view_key), fields(net = %self.network, maj_i, min_i, n_min))]
    pub async fn provision_subaddrs(
        &self,
        address: &str,
        view_key: &str,
        maj_i: u32,
        min_i: u32,
        n_min: u32,
    ) -> Result<u32, AppError> {
        let url = format!("{}/provision_subaddrs", self.user_url);
        let body = ProvisionSubaddrsRequest {
            address: address.to_string(),
            view_key: view_key.to_string(),
            maj_i,
            min_i,
            n_maj: 1,
            n_min,
            get_all: true,
        };
        // HTTP success = provisioned: the endpoint returns a non-2xx (mapped to
        // NodeError) on any failure, incl. `max_subaddresses`, so a 2xx cannot be
        // a silent no-op.
        let resp: ProvisionSubaddrsResponse =
            self.post_json(url, "provision_subaddrs", &body).await?;
        // Only major 0 has a defined contiguous-from-zero reading today, which is
        // the only major this client provisions.
        if maj_i != 0 {
            return Err(self.node_err(
                "provision_subaddrs",
                "only major account 0 can be provisioned",
            ));
        }
        resp.confirmed_minor_max().ok_or_else(|| {
            self.node_err(
                "provision_subaddrs",
                "response did not confirm a contiguous minor range for account 0",
            )
        })
    }

    /// Provision `n_min` minor indices for major account 0, retrying a transient
    /// failure with the same backoff as the import rescan. `None` when
    /// `n_min == 0` (provisioning off: the dark default); otherwise the
    /// LWS-confirmed minor ceiling. The upsert is idempotent, so a retry is safe.
    ///
    /// Capacity is probed BEFORE the first attempt so an LWS that cannot satisfy
    /// the ask fails closed with one legible error instead of three timed-out
    /// retries of a request that can never succeed.
    async fn provision_account0_with_retry(
        &self,
        address: &str,
        view_key: &str,
        n_min: u32,
    ) -> Result<Option<u32>, AppError> {
        if n_min == 0 {
            return Ok(None);
        }
        self.ensure_subaddr_capacity(n_min).await?;
        let mut attempt = 0u32;
        loop {
            match self
                .provision_subaddrs(address, view_key, 0, 0, n_min)
                .await
            {
                Ok(confirmed) => return Ok(Some(confirmed)),
                Err(e) => {
                    attempt += 1;
                    if attempt >= 3 {
                        return Err(e);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(300 * u64::from(attempt)))
                        .await;
                }
            }
        }
    }

    /// Provision account 0 and REQUIRE the confirmed ceiling to cover the ask.
    ///
    /// `n_min` indices starting at minor 0 means the ceiling must be at least
    /// `n_min - 1`. Registration promises the wallet that the whole batch is
    /// being scanned, so a short ceiling is a hard error rather than a quiet
    /// downgrade the wallet would never learn about. `None` when provisioning is
    /// off.
    pub(crate) async fn provision_account0_covering(
        &self,
        address: &str,
        view_key: &str,
        n_min: u32,
    ) -> Result<Option<u32>, AppError> {
        let Some(confirmed) = self
            .provision_account0_with_retry(address, view_key, n_min)
            .await?
        else {
            return Ok(None);
        };
        if confirmed.saturating_add(1) < n_min {
            return Err(self.node_err(
                "provision_subaddrs",
                "confirmed subaddress range is narrower than requested",
            ));
        }
        Ok(Some(confirmed))
    }

    /// Provision account 0 for an on-demand request, returning the LWS-confirmed
    /// minor ceiling verbatim. Unlike [`Self::provision_account0_covering`] a
    /// ceiling wider than the ask is reported as-is (an account provisioned
    /// earlier for a larger batch keeps its larger range; the upsert never
    /// shrinks anything), so the caller always learns the truth.
    pub async fn provision_account0(
        &self,
        address: &str,
        view_key: &str,
        n_min: u32,
    ) -> Result<u32, AppError> {
        self.provision_account0_with_retry(address, view_key, n_min)
            .await?
            .ok_or_else(|| AppError::ValidationError("subaddress count must be at least 1".into()))
    }

    /// Register an account and scan it from `start_height` (a wallet birthday).
    ///
    /// The LWS `add_account` starts every account at the chain TIP and ignores
    /// any supplied start height, so a restore needs an explicit backwards
    /// rescan. Read the post-add scan height and only rescan when strictly
    /// lowering it — honoring the `rescan` backwards-only invariant (a rescan to
    /// `height >= current` is undefined behavior in monero-lws).
    #[instrument(skip(self, view_key), fields(net = %self.network, start_height, provision_minors))]
    pub async fn import_account(
        &self,
        address: &str,
        view_key: &str,
        start_height: u64,
        provision_minors: u32,
    ) -> Result<(), AppError> {
        // Only a NEWLY added account needs the backwards rescan to its birthday
        // (monero-lws `add_account` starts every account at the chain tip). An
        // account that ALREADY exists has already been imported from its
        // birthday, so re-registration MUST be an idempotent no-op here.
        //
        // Rescanning an existing account resets its scan cursor to the birthday,
        // so a client that re-registers on every balance poll (passing the fixed
        // wallet birthday) would perpetually wipe scan progress: the account
        // reads a 0 balance, slowly re-backfills, then gets reset again on the
        // next poll and never catches up. A genuine re-restore to an EARLIER
        // birthday goes through the explicit admin `rescan` path, not this one.
        match self.account_scan_height(address).await? {
            // Already registered: never reset an existing account from here.
            //
            // It is still brought up to the required subaddress ceiling. The
            // upsert is idempotent and touches no scan state, so the
            // anti-reset-loop invariant is untouched, while an account that was
            // registered before provisioning was enabled (or before the ceiling
            // was raised) can finally be provisioned instead of being locked out
            // of the feature forever by this short-circuit.
            Some(_) => {
                self.provision_account0_covering(address, view_key, provision_minors)
                    .await?;
                Ok(())
            }
            None => {
                self.admin_add_account(address, view_key).await?;
                // Provision subaddress ranges BEFORE the backwards rescan (money
                // gate G3): the rescan re-scans forward from the birthday, so the
                // subaddresses must ALREADY be registered for the LWS to attribute
                // historical subaddress receipts in that backfill.
                //
                // The result is HELD, not propagated with `?`. The account now
                // exists at the LWS, so returning early here would strand it at
                // the chain tip: every later re-registration takes the `Some(_)`
                // branch above, answers 200, and never runs the backwards scan,
                // leaving the wallet reading a zero balance forever. The rescan
                // therefore always runs, and the provisioning failure is surfaced
                // afterwards.
                let provisioned = self
                    .provision_account0_covering(address, view_key, provision_minors)
                    .await;
                let rescanned = self.rescan_back_to(address, start_height).await;
                // A failed backfill is the graver of the two (it is the one a
                // retry can no longer reach), so it is reported first; otherwise
                // the provisioning failure is surfaced, never swallowed.
                rescanned?;
                provisioned?;
                Ok(())
            }
        }
    }

    /// Lower a freshly added account's scan cursor to `start_height`, retrying a
    /// transient failure. A no-op when the account is already at or below it
    /// (the `rescan` backwards-only invariant).
    async fn rescan_back_to(&self, address: &str, start_height: u64) -> Result<(), AppError> {
        let current = self.account_scan_height(address).await?.unwrap_or(u64::MAX);
        if start_height >= current {
            return Ok(());
        }
        // The account is added at the chain tip. If this backfill rescan fails,
        // the account is stranded at the tip: it reads a 0 balance and the
        // `Some(_)` short-circuit in `import_account` (which exists to prevent
        // the reset loop) means a later re-registration will NOT retry it. So
        // retry a transient failure here, where we still know this is a fresh
        // account that owes a backwards scan.
        let mut attempt = 0u32;
        loop {
            match self.rescan(vec![address.to_string()], start_height).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    attempt += 1;
                    if attempt >= 3 {
                        return Err(e);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(300 * u64::from(attempt)))
                        .await;
                }
            }
        }
    }

    async fn admin_add_account(&self, address: &str, view_key: &str) -> Result<(), AppError> {
        let url = format!("{}/add_account", self.admin_url);
        let body = AdminAddAccountRequest {
            auth: self.admin_key.expose().to_string(),
            params: AdminAddAccountParams {
                address: address.to_string(),
                key: view_key.to_string(),
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
pub(crate) fn sum_mempool_received(txs: &[AddressTx]) -> u64 {
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
            recipient: SubaddrIndex::default(),
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
    async fn provisioning_off_makes_no_network_call() {
        // The dark default must stay byte-identical: `n_min == 0` short-circuits
        // before the capability probe and before any request. The configured URL
        // points at a closed port, so any attempted call would surface as an
        // error rather than silently succeed.
        let client = LwsClient::monero(&cfg()).unwrap();
        assert_eq!(
            client
                .provision_account0_covering("9addr", "vk", 0)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn on_demand_provisioning_rejects_a_zero_count() {
        // A zero ask can never yield a confirmed ceiling, so it is a request
        // error rather than a silently successful no-op.
        let client = LwsClient::monero(&cfg()).unwrap();
        let err = client
            .provision_account0("9addr", "vk", 0)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::ValidationError(_)), "{err:?}");
    }

    #[test]
    fn confirmed_ceiling_is_read_from_the_response_not_the_ask() {
        // Regression guard for the echo bug: the value handed back to a client
        // must come from `all_subaddrs`, so asking for 200 against an LWS that
        // confirms only [0, 49] can never report 199.
        let resp: ProvisionSubaddrsResponse = serde_json::from_str(
            r#"{"new_subaddrs":[],"all_subaddrs":[{"key":0,"value":[[0,49]]}]}"#,
        )
        .unwrap();
        assert_eq!(resp.confirmed_minor_max(), Some(49));
    }

    #[tokio::test]
    async fn daemon_height_requires_daemon_url() {
        let client = LwsClient::monero(&cfg()).unwrap(); // daemon_url empty
        let err = client.get_blockchain_height().await.unwrap_err();
        assert!(matches!(err, AppError::NodeError(_)), "{err:?}");
    }
}
