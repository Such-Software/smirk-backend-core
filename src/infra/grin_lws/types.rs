//! Type definitions for the grin-lws (Grin light-wallet-server) client API.
//!
//! Mirrors the grin-lws HTTP surface (see grin-lws `src/api.rs`). grin-lws emits
//! every numeric field as a plain JSON integer, so amounts and indices are simple
//! `u64` (no `string_or_*` coercion is needed, unlike monero-lws).
//!
//! Request structs carry the `rewind_hash` VIEW credential, so — like the
//! monero-lws request DTOs — they deliberately omit `Debug` and can never be
//! accidentally logged.

use serde::{Deserialize, Serialize};

// ============================================================================
// Request types (internal). Credential-bearing structs deliberately omit `Debug`.
// ============================================================================

/// Body for `POST /register`.
#[derive(Serialize)]
pub(crate) struct RegisterBody {
    pub rewind_hash: String,
    /// Wallet birthday to scan from; omit to start at the current tip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_height: Option<u64>,
}

/// Body for the `rewind_hash`-keyed user endpoints (`/get_balance`,
/// `/get_unspent_outs`).
#[derive(Serialize)]
pub(crate) struct RewindHashBody {
    pub rewind_hash: String,
}

// ============================================================================
// Response types (public)
// ============================================================================

/// Response from `POST /register`.
#[derive(Debug, Deserialize)]
pub struct GrinLwsRegister {
    pub registered: bool,
    /// True if this call created a new account (vs a no-op on an existing one).
    pub new_account: bool,
    pub scan_height: u64,
    pub start_height: u64,
}

/// Response from `POST /get_balance`.
#[derive(Debug, Deserialize)]
pub struct GrinLwsBalance {
    /// Total unspent (nanogrin), including immature/locked outputs.
    pub total: u64,
    /// Spendable-now total (mature, past any lock_height at the current tip).
    pub unlocked: u64,
    /// Number of unspent outputs.
    pub count: u64,
    /// How far the scanner has processed this account.
    pub scanned_height: u64,
    /// Current chain tip.
    pub blockchain_height: u64,
}

/// A single unspent output from `POST /get_unspent_outs`, WITH the recovered
/// derivation path so the wallet can spend directly.
#[derive(Debug, Deserialize)]
pub struct GrinLwsUnspentOut {
    pub commit: String,
    pub value: u64,
    pub height: u64,
    pub mmr_index: u64,
    pub is_coinbase: bool,
    pub lock_height: u64,
    /// Spendable at the current tip (`lock_height <= blockchain_height`).
    pub spendable: bool,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub n_child: Option<u32>,
}

/// Response from `POST /get_unspent_outs`.
#[derive(Debug, Deserialize)]
pub struct GrinLwsUnspentOuts {
    #[serde(default)]
    pub outputs: Vec<GrinLwsUnspentOut>,
    pub blockchain_height: u64,
}
