//! Database entity models. These map directly to tables and are used with sqlx.
//!
//! Identity is Nostr-native: a user is keyed by `pubkey_hash` (the wallet's
//! identity pubkey), an optional `nostr_pubkey`, and an optional reserved
//! `username`. `pubkey_hash` and `seed_fingerprint` are stored HMAC-peppered at
//! rest (the pepper lives in config); the values here are already peppered.

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// ── Enums (mapped to PostgreSQL enum types) ─────────────────────────────────

/// Supported cryptocurrency assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "asset_type", rename_all = "lowercase")]
pub enum AssetType {
    Btc,
    Ltc,
    Xmr,
    Wow,
    Grin,
}

impl AssetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssetType::Btc => "btc",
            AssetType::Ltc => "ltc",
            AssetType::Xmr => "xmr",
            AssetType::Wow => "wow",
            AssetType::Grin => "grin",
        }
    }
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Grin slatepack relay status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "slatepack_status", rename_all = "snake_case")]
pub enum SlatepackStatus {
    PendingRecipient,
    PendingSender,
    Finalized,
    Expired,
    Cancelled,
}

/// Audit log action types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "audit_action", rename_all = "snake_case")]
pub enum AuditAction {
    UserCreated,
    UserLogin,
    WalletCreated,
    WalletRegistered,
    TxBroadcast,
    SessionCreated,
    SessionRevoked,
}

// ── Entities (field order matches column order) ─────────────────────────────

/// A user account. Identity is the wallet's key material, not a platform login.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    /// Reserved `@handle` (backs NIP-05). Unique, optional.
    pub username: Option<String>,
    /// Peppered hash of the wallet identity pubkey. Unique, optional.
    pub pubkey_hash: Option<String>,
    /// The user's Nostr public key (hex). Unique, optional.
    pub nostr_pubkey: Option<String>,
    /// Approximate wallet creation time, to bound chain scans.
    pub wallet_birthday: Option<DateTime<Utc>>,
    /// Peppered seed fingerprint, for restore lookup. Unique, optional.
    pub seed_fingerprint: Option<String>,
    /// Monero scan start height (skip pre-birthday blocks).
    pub xmr_start_height: Option<i64>,
    /// Wownero scan start height.
    pub wow_start_height: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// A wallet associated with a user.
///
/// Non-custodial: we store the public address and (for XMR/WOW) the view key
/// for balance scanning. We NEVER store a spend key or seed.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Wallet {
    pub id: Uuid,
    pub user_id: Uuid,
    pub asset: AssetType,
    pub address: String,
    /// View key (XMR/WOW only) for balance scanning.
    pub view_key: Option<String>,
    /// HD derivation index (BTC/LTC).
    pub derivation_index: Option<i32>,
    pub registered_with_node: bool,
    pub registration_error: Option<String>,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A session backing a JWT refresh token.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    /// Peppered hash of the refresh token (never the token itself).
    pub refresh_token_hash: String,
    /// Client kind: `extension`, `web`, or `nostr`.
    pub platform: String,
    pub device_info: Option<String>,
    pub ip_address: Option<IpNetwork>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: DateTime<Utc>,
}

/// A user's per-asset public key, so others can send to them.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct UserKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub asset: AssetType,
    /// The public key (format depends on asset).
    pub public_key: String,
    /// Public spend key (XMR/WOW).
    pub public_spend_key: Option<String>,
    /// `primary` or `backup`.
    pub key_type: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A Grin slatepack relayed between two parties for an interactive transaction.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct GrinSlatepack {
    pub id: Uuid,
    pub slate_id: String,
    pub sender_user_id: Uuid,
    /// Recipient user (if registered on this backend).
    pub recipient_user_id: Option<Uuid>,
    /// Recipient slatepack address (if not registered here).
    pub recipient_address: Option<String>,
    pub slatepack_content: String,
    pub amount_nanogrin: i64,
    pub status: SlatepackStatus,
    pub response_slatepack: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub finalized_at: Option<DateTime<Utc>>,
    pub tx_hash: Option<String>,
}

/// Audit log entry for security-relevant actions.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: AuditAction,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<IpNetwork>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ── Input structs (no auto-generated fields) ────────────────────────────────

/// Input for creating a new user. Peppered values are supplied by the db layer.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: Option<String>,
    pub pubkey_hash: Option<String>,
    pub nostr_pubkey: Option<String>,
    pub wallet_birthday: Option<DateTime<Utc>>,
    pub seed_fingerprint: Option<String>,
    pub xmr_start_height: Option<i64>,
    pub wow_start_height: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewWallet {
    pub user_id: Uuid,
    pub asset: AssetType,
    pub address: String,
    pub view_key: Option<String>,
    pub derivation_index: Option<i32>,
    pub label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewSession {
    pub user_id: Uuid,
    pub refresh_token_hash: String,
    pub platform: String,
    pub device_info: Option<String>,
    pub ip_address: Option<IpNetwork>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewUserKey {
    pub user_id: Uuid,
    pub asset: AssetType,
    pub public_key: String,
    pub public_spend_key: Option<String>,
    pub key_type: String,
}

#[derive(Debug, Clone)]
pub struct NewGrinSlatepack {
    pub slate_id: String,
    pub sender_user_id: Uuid,
    pub recipient_user_id: Option<Uuid>,
    pub recipient_address: Option<String>,
    pub slatepack_content: String,
    pub amount_nanogrin: i64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewAuditLog {
    pub user_id: Option<Uuid>,
    pub action: AuditAction,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<IpNetwork>,
    pub user_agent: Option<String>,
}
