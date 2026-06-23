//! Type definitions for the LWS (light-wallet-server) API.
//!
//! monero-lws sometimes encodes numeric fields as JSON strings (e.g. `"0"`),
//! so amounts use the `string_or_*` fail-closed deserializers: a malformed or
//! out-of-range value becomes a deserialization *error*, never a panic and
//! never a silently-wrong number. All amounts are atomic units (piconero /
//! wownoshi) carried as `u64`.
//!
//! Request structs that carry a secret (`auth` admin key, `view_key`) do **not**
//! derive `Debug`, so they cannot be accidentally logged.

use serde::{Deserialize, Serialize};

// ============================================================================
// Serde helpers — string-or-integer, fail-closed (Err, never panic)
// ============================================================================

/// Deserialize a `u64` that may arrive as a JSON string or integer.
pub mod string_or_u64 {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrInt {
            String(String),
            Int(u64),
        }
        match StringOrInt::deserialize(deserializer)? {
            StringOrInt::String(s) => s.parse().map_err(serde::de::Error::custom),
            StringOrInt::Int(n) => Ok(n),
        }
    }
}

/// Deserialize a `u64` that may arrive as a string, integer, or null/missing
/// (null/missing → 0).
pub mod string_or_u64_default {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrIntOrNull {
            String(String),
            Int(u64),
            Null,
        }
        match Option::<StringOrIntOrNull>::deserialize(deserializer)? {
            Some(StringOrIntOrNull::String(s)) => s.parse().map_err(serde::de::Error::custom),
            Some(StringOrIntOrNull::Int(n)) => Ok(n),
            Some(StringOrIntOrNull::Null) | None => Ok(0),
        }
    }
}

/// Deserialize a `u32` that may arrive as a JSON string or integer.
pub mod string_or_u32 {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrInt {
            String(String),
            Int(u32),
        }
        match StringOrInt::deserialize(deserializer)? {
            StringOrInt::String(s) => s.parse().map_err(serde::de::Error::custom),
            StringOrInt::Int(n) => Ok(n),
        }
    }
}

/// Deserialize a `u8` that may arrive as a string, integer, or null/missing
/// (null/missing → 0).
pub mod string_or_u8_default {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u8, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrIntOrNull {
            String(String),
            Int(u8),
            Null,
        }
        match Option::<StringOrIntOrNull>::deserialize(deserializer)? {
            Some(StringOrIntOrNull::String(s)) => s.parse().map_err(serde::de::Error::custom),
            Some(StringOrIntOrNull::Int(n)) => Ok(n),
            Some(StringOrIntOrNull::Null) | None => Ok(0),
        }
    }
}

// ============================================================================
// Network
// ============================================================================

/// A CryptoNote network served by an LWS. Monero and Wownero share the LWS API
/// (Wownero is a Monero fork); the distinction is the atomic-unit scale and
/// daemon ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoNoteNetwork {
    Monero,
    Wownero,
}

impl std::fmt::Display for CryptoNoteNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monero => f.write_str("monero"),
            Self::Wownero => f.write_str("wownero"),
        }
    }
}

// ============================================================================
// Request types (internal). Secret-bearing structs deliberately omit `Debug`.
// ============================================================================

/// Admin `add_account`: directly add + activate an account (view-only scan).
#[derive(Serialize)]
pub(crate) struct AdminAddAccountRequest {
    pub auth: String,
    pub params: AdminAddAccountParams,
}

#[derive(Serialize)]
pub(crate) struct AdminAddAccountParams {
    pub address: String,
    /// The private view key.
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_height: Option<u64>,
}

#[derive(Serialize)]
pub(crate) struct GetAddressInfoRequest {
    pub address: String,
    pub view_key: String,
}

#[derive(Serialize)]
pub(crate) struct GetAddressTxsRequest {
    pub address: String,
    pub view_key: String,
}

#[derive(Serialize)]
pub(crate) struct GetUnspentOutsRequest {
    pub address: String,
    pub view_key: String,
    /// "0" for all.
    pub amount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixin: Option<u32>,
    pub use_dust: bool,
    pub dust_threshold: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct GetRandomOutsRequest {
    pub count: u32,
    pub amounts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SubmitRawTxRequest {
    /// Hex-encoded transaction blob.
    pub tx: String,
}

#[derive(Serialize)]
pub(crate) struct ListAccountsBody {
    pub auth: String,
}

#[derive(Serialize)]
pub(crate) struct ModifyAccountStatusRequest {
    pub auth: String,
    pub params: ModifyAccountStatusParams,
}

#[derive(Serialize)]
pub(crate) struct ModifyAccountStatusParams {
    pub addresses: Vec<String>,
    pub status: AccountStatus,
}

#[derive(Serialize)]
pub(crate) struct RescanRequest {
    pub auth: String,
    pub params: RescanParams,
}

#[derive(Serialize)]
pub(crate) struct RescanParams {
    pub addresses: Vec<String>,
    /// Target start height — MUST be strictly less than the account's current
    /// `scan_height`. Higher values are undefined behavior (see `LwsClient::rescan`).
    pub height: u64,
}

// ============================================================================
// Response types (public)
// ============================================================================

/// Response from `get_address_txs`.
#[derive(Debug, Clone, Deserialize)]
pub struct AddressTxsResponse {
    #[serde(default)]
    pub transactions: Vec<AddressTx>,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub total_received: u64,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub scanned_height: u64,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub blockchain_height: u64,
}

/// A transaction from `get_address_txs`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddressTx {
    pub hash: String,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub height: u64,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub total_received: u64,
    /// "Possible" sent — outputs that MAY be spent. LWS cannot confirm spends
    /// without the spend key, so this is never treated as authoritative.
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub total_sent: u64,
    #[serde(default)]
    pub mempool: bool,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub unlock_time: u64,
    #[serde(default)]
    pub payment_id: Option<String>,
    /// Candidate spends — must be verified client-side with the spend key.
    #[serde(default)]
    pub spent_outputs: Vec<SpentOutput>,
}

/// A candidate spent output from LWS (verify with the spend key before trusting).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SpentOutput {
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub amount: u64,
    pub key_image: String,
    pub tx_pub_key: String,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub out_index: u64,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub mixin: u64,
}

/// Address info (balance and scan state) from `get_address_info`.
#[derive(Debug, Clone, Deserialize)]
pub struct AddressInfo {
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub locked_funds: u64,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub total_received: u64,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub total_sent: u64,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub scanned_height: u64,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub start_height: u64,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub transaction_count: u64,
    #[serde(default)]
    pub scanned_block_hash: String,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub blockchain_height: u64,
}

impl AddressInfo {
    /// Balance in atomic units.
    ///
    /// Uses `total_received` only, NOT `total_received - total_sent`: LWS's
    /// `total_sent` is "possible spends" (it cannot confirm a spend without the
    /// spend key). As a view-only service we report received funds.
    pub fn balance(&self) -> u64 {
        self.total_received
    }

    /// Unlocked (confirmed) balance = received minus locked (unconfirmed) funds.
    pub fn unlocked_balance(&self) -> u64 {
        self.total_received.saturating_sub(self.locked_funds)
    }
}

/// An unspent output from LWS.
#[derive(Debug, Clone, Deserialize)]
pub struct UnspentOutput {
    #[serde(deserialize_with = "string_or_u64::deserialize")]
    pub amount: u64,
    pub public_key: String,
    pub tx_pub_key: String,
    #[serde(deserialize_with = "string_or_u32::deserialize")]
    pub index: u32,
    #[serde(deserialize_with = "string_or_u64::deserialize")]
    pub global_index: u64,
    #[serde(deserialize_with = "string_or_u64::deserialize")]
    pub height: u64,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub tx_hash: String,
    #[serde(default)]
    pub rct: String,
    /// Key images LWS has seen on-chain that may correspond to this output being
    /// spent. Non-empty ⇒ likely spent.
    #[serde(default)]
    pub spend_key_images: Vec<String>,
}

/// Response from `get_unspent_outs`.
#[derive(Debug, Deserialize)]
pub struct UnspentOutsResponse {
    #[serde(default)]
    pub outputs: Vec<UnspentOutput>,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub per_byte_fee: u64,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub fee_mask: u64,
    #[serde(default, deserialize_with = "string_or_u8_default::deserialize")]
    pub fork_version: u8,
}

/// A decoy output for ring selection.
#[derive(Debug, Clone, Deserialize)]
pub struct RandomOutput {
    #[serde(deserialize_with = "string_or_u64::deserialize")]
    pub global_index: u64,
    pub public_key: String,
    pub rct: String,
}

/// Response from `get_random_outs`.
#[derive(Debug, Deserialize)]
pub struct RandomOutsResponse {
    #[serde(default)]
    pub amount_outs: Vec<AmountOuts>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AmountOuts {
    pub amount: String,
    pub outputs: Vec<RandomOutput>,
}

/// An account entry from `list_accounts`.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountEntry {
    pub address: String,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub scan_height: u64,
    #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
    pub access_time: u64,
}

/// Response from `list_accounts`.
#[derive(Debug, Deserialize)]
pub struct ListAccountsResponse {
    #[serde(default)]
    pub active: Vec<AccountEntry>,
    #[serde(default)]
    pub hidden: Vec<AccountEntry>,
    #[serde(default)]
    pub inactive: Vec<AccountEntry>,
}

/// Account scan status for `modify_account_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    /// Actively scanning.
    Active,
    /// Preserved but not scanning (reactivatable).
    Inactive,
    /// Not scanning, minimal storage.
    Hidden,
}

#[cfg(test)]
mod tests {
    use super::*;

    // The string_or_* helpers must FAIL (Err), never panic, on hostile input —
    // they run on bytes from a possibly-malicious LWS.

    #[derive(Deserialize)]
    struct U64Holder {
        #[serde(deserialize_with = "string_or_u64::deserialize")]
        v: u64,
    }

    #[test]
    fn string_or_u64_accepts_string_and_int() {
        assert_eq!(
            serde_json::from_str::<U64Holder>(r#"{"v":"42"}"#)
                .unwrap()
                .v,
            42
        );
        assert_eq!(
            serde_json::from_str::<U64Holder>(r#"{"v":42}"#).unwrap().v,
            42
        );
    }

    #[test]
    fn string_or_u64_rejects_garbage_without_panic() {
        // Non-numeric string, overflow, float, and bool all error cleanly.
        assert!(serde_json::from_str::<U64Holder>(r#"{"v":"not-a-number"}"#).is_err());
        assert!(
            serde_json::from_str::<U64Holder>(r#"{"v":"99999999999999999999999999"}"#).is_err()
        );
        assert!(serde_json::from_str::<U64Holder>(r#"{"v":"-1"}"#).is_err());
        assert!(serde_json::from_str::<U64Holder>(r#"{"v":true}"#).is_err());
    }

    #[derive(Deserialize)]
    struct U64DefHolder {
        #[serde(default, deserialize_with = "string_or_u64_default::deserialize")]
        v: u64,
    }

    #[test]
    fn string_or_u64_default_handles_null_and_missing() {
        assert_eq!(
            serde_json::from_str::<U64DefHolder>(r#"{"v":null}"#)
                .unwrap()
                .v,
            0
        );
        assert_eq!(serde_json::from_str::<U64DefHolder>(r#"{}"#).unwrap().v, 0);
        assert_eq!(
            serde_json::from_str::<U64DefHolder>(r#"{"v":"7"}"#)
                .unwrap()
                .v,
            7
        );
        // Garbage still errors (default is only for null/missing).
        assert!(serde_json::from_str::<U64DefHolder>(r#"{"v":"x"}"#).is_err());
    }

    #[test]
    fn balance_uses_received_not_difference() {
        let info = AddressInfo {
            locked_funds: 1000,
            total_received: 10_000,
            total_sent: 3000,
            scanned_height: 100,
            start_height: 50,
            transaction_count: 5,
            scanned_block_hash: String::new(),
            blockchain_height: 100,
        };
        assert_eq!(info.balance(), 10_000);
        assert_eq!(info.unlocked_balance(), 9000);
    }
}
