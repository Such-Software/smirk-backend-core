//! Grin chain access — **view-only**, for a non-custodial backend.
//!
//! The backend holds no Grin spend key. Grin has had view/spend separation since
//! 2021 (`grin_keychain::ViewKey`): a wallet exports a `rewind_hash` (derived from
//! its *public* root key) that lets a holder recognize the wallet's outputs and
//! read their amounts, but **not** spend them. grin-wallet's Owner API
//! `scan_rewind_hash(rewind_hash, start_height)` does the chain scan (rangeproof
//! rewind) and returns a [`ViewWallet`]; this client drives that, plus node
//! status and broadcast. Spending (input selection, kernel signing) happens in
//! the wallet, locally — never here. See `docs/private/GRIN_LWS_DESIGN.md`.
//!
//! The Owner API v3 transport is an ECDH (secp256k1) handshake + AES-256-GCM
//! channel; the secure session is initialized once (TOCTOU-free), the nonce
//! counter advances with `checked_add` (never reused), and no key / password /
//! response body is ever logged. Every response read is size-bounded.

mod api;
mod secure;

use std::time::Duration;

use serde::Deserialize;
use tokio::sync::RwLock;

use crate::config::GrinConfig;
use crate::core::secret::Secret;
use crate::error::AppError;

/// Per-request / connect deadlines (grin-wallet or node may be down).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard cap on any grin response body (enforced while streaming). A `ViewWallet`
/// for a busy wallet is the largest legitimate payload and sits well under this.
const MAX_GRIN_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Secure-session state for the Owner API v3 encrypted channel.
struct SecureSession {
    /// AES-256 key = ECDH shared secret (raw x-coordinate, per Grin).
    shared_key: [u8; 32],
    /// Monotonic AES-GCM nonce counter; advanced with `checked_add`.
    nonce_counter: u64,
}

/// View-only Grin client. Cheap to clone is NOT supported (holds session locks);
/// construct once and share via `Arc`.
pub struct GrinClient {
    // Wallet Owner API (v3 encrypted) — for the view-only scan.
    owner_api_url: String,
    owner_api_secret: Secret,
    wallet_password: Secret,
    // Node APIs — status (Owner) + broadcast (Foreign).
    node_api_url: String,
    node_api_user: String,
    node_api_pass: Secret,
    node_foreign_api_url: String,
    node_foreign_api_secret: Secret,
    http: reqwest::Client,
    /// Cached `open_wallet` token (non-poisoning async lock).
    session_token: RwLock<Option<String>>,
    /// ECDH/AES-GCM secure session (non-poisoning async lock).
    secure_session: RwLock<Option<SecureSession>>,
}

impl GrinClient {
    /// Build a view-only Grin client from config. No network I/O until a call.
    pub fn new(cfg: &GrinConfig) -> Result<Self, AppError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|_| AppError::NodeError("failed to build Grin HTTP client".into()))?;
        Ok(Self {
            owner_api_url: cfg.owner_api_url.clone(),
            owner_api_secret: Secret::new(cfg.owner_api_secret.clone()),
            wallet_password: Secret::new(cfg.wallet_password.clone()),
            node_api_url: cfg.node_api_url.clone(),
            node_api_user: cfg.node_api_user.clone(),
            node_api_pass: Secret::new(cfg.node_api_pass.clone()),
            node_foreign_api_url: cfg.node_foreign_api_url.clone(),
            node_foreign_api_secret: Secret::new(cfg.node_foreign_api_secret.clone()),
            http,
            session_token: RwLock::new(None),
            secure_session: RwLock::new(None),
        })
    }
}

// ── public result types (mirror grin-wallet) ────────────────────────────────

/// Result of a view-only scan (`scan_rewind_hash`): the outputs a `rewind_hash`
/// recognizes, their total, and the resume index for the next incremental scan.
#[derive(Debug, Clone, Deserialize)]
pub struct ViewWallet {
    pub rewind_hash: String,
    #[serde(default)]
    pub output_result: Vec<ViewWalletOutputResult>,
    pub total_balance: u64,
    pub last_pmmr_index: u64,
}

/// A single output recovered by a view-only scan. Amounts are nanogrin (`u64`).
#[derive(Debug, Clone, Deserialize)]
pub struct ViewWalletOutputResult {
    pub commit: String,
    pub value: u64,
    pub height: u64,
    pub mmr_index: u64,
    #[serde(default)]
    pub is_coinbase: bool,
    #[serde(default)]
    pub lock_height: u64,
}

impl ViewWalletOutputResult {
    /// Confirmations at `tip_height`; `0` if the output claims a block beyond the
    /// tip (a lagging/inconsistent node) rather than a bogus count.
    pub fn confirmations(&self, tip_height: u64) -> u64 {
        if self.height == 0 || self.height > tip_height {
            return 0;
        }
        tip_height.saturating_sub(self.height).saturating_add(1)
    }
}

/// Node status (subset of grin node `get_status`).
#[derive(Debug, Clone, Deserialize)]
pub struct GrinStatus {
    pub tip: GrinTip,
    #[serde(default)]
    pub sync_status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrinTip {
    pub height: u64,
}
