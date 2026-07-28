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

/// Deserialize a `u32` that may arrive as a string, integer, or null/missing
/// (null/missing → 0). Mirrors [`string_or_u64_default`] for the subaddress
/// index fields, which fail OPEN to 0 (the primary index) so an unexpected or
/// absent `recipient` encoding never breaks response parsing (money gate G2).
///
/// "Fail open" here is total, and deliberately so: **every** shape that is not a
/// parseable in-range unsigned integer degrades to 0, including a negative
/// number, a float, a value above `u32::MAX`, an unparseable string, or a
/// structurally unexpected value. Anything less would let one malformed index
/// abort the deserialization of the WHOLE `get_unspent_outs` /
/// `get_address_txs` response, which would hide a user's entire balance rather
/// than mislabel one output's index.
///
/// The safety of defaulting to the primary index rests on this holding only
/// while subaddress provisioning is off. Once an account is knowingly
/// provisioned for subaddresses, an unlabelled output must NOT be silently
/// treated as primary (it would produce the wrong key image); that is enforced
/// above this layer, not here.
pub mod string_or_u32_default {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrIntOrNull {
            String(String),
            Int(u32),
            Null,
            /// Catch-all so a negative / float / out-of-range / structurally
            /// unexpected value degrades to 0 instead of failing the parse.
            /// `IgnoredAny` consumes any shape without allocating and without
            /// leaving an unread field behind.
            Other(serde::de::IgnoredAny),
        }
        match Option::<StringOrIntOrNull>::deserialize(deserializer)? {
            // An unparseable string degrades to the primary index rather than
            // erroring, for the same whole-response reason documented above.
            Some(StringOrIntOrNull::String(s)) => Ok(s.parse().unwrap_or(0)),
            Some(StringOrIntOrNull::Int(n)) => Ok(n),
            Some(StringOrIntOrNull::Null) | Some(StringOrIntOrNull::Other(_)) | None => Ok(0),
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
}

#[derive(Serialize)]
pub(crate) struct GetAddressInfoRequest {
    pub address: String,
    pub view_key: String,
}

/// USER-endpoint `provision_subaddrs` request (monero-lws `/provision_subaddrs`,
/// confirmed a USER endpoint keyed by `address` + `view_key` — not admin — in
/// `monero-lws/src/rest_server.cpp` `endpoints[]` (`is_admin = false`) and its
/// `provision_subaddrs_request` wire reader in `src/rpc/light_wallet.cpp`).
///
/// Provisions the `[min_i .. min_i + n_min)` minor range for `n_maj` major
/// indices starting at `maj_i`, so the LWS attributes subaddress receipts.
///
/// Carries the private `view_key`, so it deliberately omits `Debug` (crate
/// convention for secret-bearing request structs).
#[derive(Serialize)]
pub(crate) struct ProvisionSubaddrsRequest {
    pub address: String,
    pub view_key: String,
    /// First major (account) index to provision.
    pub maj_i: u32,
    /// First minor index within each major to provision.
    pub min_i: u32,
    /// Number of major indices to cover (1 = account 0 only).
    pub n_maj: u32,
    /// Number of minor indices per major. `n_maj * n_min` must not exceed the
    /// LWS `--max-subaddresses` (defaults to 0 = subaddresses DISABLED), else
    /// the LWS returns a `max_subaddresses` error.
    pub n_min: u32,
    /// Whether the LWS should echo back the full subaddress set. Sent as `true`:
    /// `new_subaddrs` lists only the ranges a call NEWLY added (empty on an
    /// idempotent repeat), so `all_subaddrs` is the only field that can confirm
    /// the ceiling actually in force for the account.
    pub get_all: bool,
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

/// A subaddress index `(major, minor)` as delivered by monero-lws in the
/// `recipient` field of an output/tx (wire shape `{"maj_i":u32,"min_i":u32}`,
/// per `db::address_index` in `monero-lws/src/db/data.cpp`).
///
/// Both fields fail OPEN to `0` (the primary index) when absent, null, or
/// otherwise unexpectedly encoded, and `#[serde(default)]` on the carrying field
/// means an entirely absent `recipient` yields `(0, 0)` while the surrounding
/// response STILL parses (money gate G2: a receive is never dropped because of an
/// unexpected recipient encoding). A pre-subaddress LWS that omits the field, or
/// a primary-address receive, is therefore attributed to account 0 / index 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct SubaddrIndex {
    #[serde(default, deserialize_with = "string_or_u32_default::deserialize")]
    pub maj_i: u32,
    #[serde(default, deserialize_with = "string_or_u32_default::deserialize")]
    pub min_i: u32,
}

/// One entry of a monero-lws subaddress range list.
///
/// Wire shape (`db::subaddress_dict` = `std::pair<major_index, index_ranges>`,
/// written by `map_subaddress_dict` in `monero-lws/src/db/data.cpp`):
///
/// ```json
/// {"key": 0, "value": [[0, 199]]}
/// ```
///
/// `key` is the major (account) index; `value` is a list of INCLUSIVE
/// `[first_minor, last_minor]` ranges. `value` is written with
/// `wire::optional_field`, so it is absent when the entry carries no ranges.
///
/// Parsing is deliberately STRICT here (unlike the fail-open `recipient`
/// index): this type is only used to read back the ceiling the LWS actually
/// confirmed, and a ceiling that is guessed from a malformed body would let the
/// wallet hand out subaddresses the LWS is not scanning; funds would arrive
/// invisibly. A malformed entry must be an error, never a default.
#[derive(Debug, Clone, Deserialize)]
pub struct SubaddrRangeEntry {
    /// Major (account) index this range list belongs to.
    #[serde(deserialize_with = "string_or_u32::deserialize")]
    pub key: u32,
    /// Inclusive `[first, last]` minor ranges. Absent ⇒ no ranges.
    #[serde(default)]
    pub value: Vec<[u32; 2]>,
}

/// Response from monero-lws `provision_subaddrs` (`new_subaddrs_response`:
/// `{"new_subaddrs":[...],"all_subaddrs":[...]}`, see
/// `rpc::write_bytes(wire::json_writer&, const new_subaddrs_response&)` in
/// `monero-lws/src/rpc/light_wallet.cpp`).
///
/// `new_subaddrs` holds ONLY the ranges this call newly added (an idempotent
/// re-provision of an existing range returns an empty list), so it can never be
/// used to learn the account's actual ceiling. `all_subaddrs` holds the full
/// current set, and is populated only when the request sets `get_all: true`.
#[derive(Debug, Default, Deserialize)]
pub struct ProvisionSubaddrsResponse {
    /// Ranges newly added by this call (empty on an idempotent repeat).
    ///
    /// Documents the wire contract and is asserted in unit tests; deliberately
    /// NOT consulted in production, since an empty list means "nothing new",
    /// not "nothing provisioned".
    #[allow(dead_code)]
    #[serde(default)]
    pub new_subaddrs: Vec<SubaddrRangeEntry>,
    /// The account's complete current range set (requires `get_all: true`).
    #[serde(default)]
    pub all_subaddrs: Vec<SubaddrRangeEntry>,
}

impl ProvisionSubaddrsResponse {
    /// The CONFIRMED contiguous minor ceiling for major account 0: the highest
    /// minor index `m` such that every index in `0..=m` is provisioned at the
    /// LWS. `None` when that cannot be established (major 0 absent, or its
    /// ranges do not start at minor 0).
    ///
    /// Contiguity is the whole point: monero-lws stores an account's minors as a
    /// list of disjoint ranges, so `[[0,99],[200,299]]` has a maximum of `299`
    /// while indices `100..=199` are NOT scanned. Reporting `299` as the ceiling
    /// would let the wallet hand out an unscanned subaddress and receive funds
    /// it can never see. Only the run starting at `0` is reported.
    pub fn confirmed_minor_max(&self) -> Option<u32> {
        let entry = self.all_subaddrs.iter().find(|e| e.key == 0)?;
        let mut ranges: Vec<[u32; 2]> = entry
            .value
            .iter()
            .copied()
            .filter(|r| r[0] <= r[1]) // drop an inverted range rather than trust it
            .collect();
        ranges.sort_unstable();
        let first = ranges.first()?;
        if first[0] != 0 {
            return None;
        }
        let mut ceiling = first[1];
        for r in ranges.iter().skip(1) {
            // Extend only across a range that starts at or before the next
            // index; anything beyond that is a gap and ends the run.
            if r[0] > ceiling.saturating_add(1) {
                break;
            }
            ceiling = ceiling.max(r[1]);
        }
        Some(ceiling)
    }
}

/// Response from the monero-lws USER endpoint `/get_version`
/// (`rpc::get_version_response`, `src/rpc/light_wallet.cpp`). Only
/// `max_subaddresses` is consumed: it is the LWS's `--max-subaddresses` option
/// (default `0` = subaddresses DISABLED) and is the hard ceiling every
/// `provision_subaddrs` call is checked against server-side
/// (`rest_server.cpp`: `if (options.max_subaddresses < n_major * n_minor)
/// return {lws::error::max_subaddresses};`).
///
/// Parsed strictly: an absent or malformed `max_subaddresses` must not be read
/// as "capable", so the field has no default.
#[derive(Debug, Deserialize)]
pub struct LwsVersionResponse {
    /// Maximum `n_maj * n_min` this LWS will provision for one account.
    #[serde(deserialize_with = "string_or_u32::deserialize")]
    pub max_subaddresses: u32,
}

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
    /// Subaddress index this tx was received at. Absent/garbage → `(0, 0)`
    /// (fails OPEN; the response still parses — money gate G2).
    #[serde(default)]
    pub recipient: SubaddrIndex,
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
    /// Subaddress index of the output BEING SPENT, so a client can recompute the
    /// right key image for it.
    ///
    /// monero-lws names this field `sender` on the wire:
    /// `rpc::write_bytes(wire::json_writer&, const transaction_spend&)` in
    /// `src/rpc/light_wallet.cpp` writes
    /// `wire::field("sender", std::cref(self.possible_spend.sender))`, and
    /// `db::spend::sender` is filled from `user.get_spendable(output_id)` in
    /// `src/util/ownership_test.cpp`, i.e. the index the SPENT output was
    /// received at, not the enclosing transaction's change index.
    ///
    /// `recipient` is accepted as an alias for forward compatibility. Absent
    /// (a pre-subaddress LWS) → `(0, 0)`, so the surrounding response still
    /// parses; the client-side contract decides whether an unlabelled spend is
    /// usable, since a wrong index yields a key image that never matches.
    #[serde(default, alias = "recipient")]
    pub sender: SubaddrIndex,
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
    /// Subaddress index this output was received at. Absent/garbage → `(0, 0)`
    /// (fails OPEN; the response still parses — money gate G2).
    #[serde(default)]
    pub recipient: SubaddrIndex,
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

    // ── subaddress recipient: fail-OPEN to (0,0) (money gate G2) ──────────────

    #[test]
    fn recipient_absent_defaults_to_zero_and_output_still_parses() {
        // A `get_unspent_outs` output with NO `recipient` field (pre-subaddress
        // LWS) must parse, attributing the output to account 0 / index 0.
        let json = r#"{
            "amount": "1000000000000",
            "public_key": "aa",
            "tx_pub_key": "bb",
            "index": 3,
            "global_index": 42,
            "height": 100
        }"#;
        let out: UnspentOutput = serde_json::from_str(json).unwrap();
        assert_eq!(out.recipient, SubaddrIndex { maj_i: 0, min_i: 0 });
        assert_eq!(out.amount, 1_000_000_000_000);
    }

    #[test]
    fn recipient_absent_defaults_to_zero_and_full_txs_response_still_parses() {
        // A full `get_address_txs` response whose tx omits `recipient` must
        // still parse end-to-end (the whole response is not rejected — G2).
        let json = r#"{
            "transactions": [
                {"hash": "h1", "height": 10, "total_received": "5"},
                {"hash": "h2", "height": 11, "total_received": "7", "recipient": {"maj_i": 0, "min_i": 4}}
            ],
            "total_received": "12",
            "scanned_height": 11,
            "blockchain_height": 11
        }"#;
        let resp: AddressTxsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.transactions.len(), 2);
        assert_eq!(resp.transactions[0].recipient, SubaddrIndex::default());
        assert_eq!(
            resp.transactions[1].recipient,
            SubaddrIndex { maj_i: 0, min_i: 4 }
        );
        assert_eq!(resp.total_received, 12);
    }

    #[test]
    fn recipient_accepts_string_or_int_and_null_fails_open() {
        // String-encoded, null, and integer indices all fail open cleanly.
        let s: SubaddrIndex = serde_json::from_str(r#"{"maj_i":"1","min_i":"9"}"#).unwrap();
        assert_eq!(s, SubaddrIndex { maj_i: 1, min_i: 9 });
        let n: SubaddrIndex = serde_json::from_str(r#"{"maj_i":null,"min_i":9}"#).unwrap();
        assert_eq!(n, SubaddrIndex { maj_i: 0, min_i: 9 });
        let e: SubaddrIndex = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(e, SubaddrIndex::default());
    }

    #[test]
    fn recipient_malformed_index_degrades_to_primary_and_never_breaks_the_response() {
        // Every shape that is not a parseable in-range unsigned integer must
        // degrade to 0 rather than abort the parse. Before this was total, a
        // single negative / float / oversized index would fail the WHOLE
        // `get_unspent_outs` response, hiding the user's entire balance.
        for bad in [
            r#"{"maj_i":-1,"min_i":2}"#,             // negative
            r#"{"maj_i":1.5,"min_i":2}"#,            // float
            r#"{"maj_i":4294967296,"min_i":2}"#,     // > u32::MAX
            r#"{"maj_i":"not-a-number","min_i":2}"#, // unparseable string
            r#"{"maj_i":{"nested":1},"min_i":2}"#,   // structurally unexpected
            r#"{"maj_i":[1],"min_i":2}"#,            // array
            r#"{"maj_i":true,"min_i":2}"#,           // bool
        ] {
            let v: SubaddrIndex =
                serde_json::from_str(bad).unwrap_or_else(|e| panic!("{bad} must parse, got {e}"));
            assert_eq!(v.maj_i, 0, "{bad} should degrade maj_i to primary");
            assert_eq!(v.min_i, 2, "{bad} must not disturb the sibling field");
        }
    }

    #[test]
    fn malformed_recipient_still_yields_a_usable_unspent_output() {
        // The whole-response property, which is the one that actually protects
        // the balance: a garbage index must not cost us the output itself.
        let json = r#"{
            "amount": "1000000000000",
            "public_key": "aa",
            "tx_pub_key": "bb",
            "index": 3,
            "global_index": 42,
            "height": 100,
            "recipient": {"maj_i": -5, "min_i": 1.25}
        }"#;
        let out: UnspentOutput = serde_json::from_str(json).expect("output must still parse");
        assert_eq!(out.amount, 1_000_000_000_000);
        assert_eq!(out.recipient, SubaddrIndex::default());
    }

    // ── provision_subaddrs request / response wire shapes ─────────────────────

    #[test]
    fn provision_request_serializes_expected_fields() {
        let req = ProvisionSubaddrsRequest {
            address: "9addr".into(),
            view_key: "vk".into(),
            maj_i: 0,
            min_i: 0,
            n_maj: 1,
            n_min: 200,
            get_all: true,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["address"], "9addr");
        assert_eq!(v["view_key"], "vk");
        assert_eq!(v["maj_i"], 0);
        assert_eq!(v["min_i"], 0);
        assert_eq!(v["n_maj"], 1);
        assert_eq!(v["n_min"], 200);
        assert_eq!(v["get_all"], true);
    }

    #[test]
    fn provision_response_parses_and_tolerates_missing_lists() {
        let full: ProvisionSubaddrsResponse = serde_json::from_str(
            r#"{"new_subaddrs":[{"key":0,"value":[[0,199]]}],"all_subaddrs":[]}"#,
        )
        .unwrap();
        assert_eq!(full.new_subaddrs.len(), 1);
        assert_eq!(full.new_subaddrs[0].key, 0);
        assert_eq!(full.new_subaddrs[0].value, vec![[0, 199]]);
        assert!(full.all_subaddrs.is_empty());
        // An empty object (either list absent) still parses.
        let empty: ProvisionSubaddrsResponse = serde_json::from_str(r#"{}"#).unwrap();
        assert!(empty.new_subaddrs.is_empty() && empty.all_subaddrs.is_empty());
        // `value` is written with `wire::optional_field`, so it can be absent.
        let no_value: ProvisionSubaddrsResponse =
            serde_json::from_str(r#"{"all_subaddrs":[{"key":0}]}"#).unwrap();
        assert!(no_value.all_subaddrs[0].value.is_empty());
    }

    // ── the confirmed ceiling is READ from the LWS, never assumed ─────────────

    fn all(json: &str) -> ProvisionSubaddrsResponse {
        serde_json::from_str(json).expect("valid provision response")
    }

    #[test]
    fn confirmed_minor_max_reads_the_contiguous_run_from_zero() {
        // The ordinary case: one range [0, 199] => ceiling 199 (200 indices).
        assert_eq!(
            all(r#"{"all_subaddrs":[{"key":0,"value":[[0,199]]}]}"#).confirmed_minor_max(),
            Some(199)
        );
        // Major 0 is selected even when other majors are present and listed first.
        assert_eq!(
            all(r#"{"all_subaddrs":[{"key":3,"value":[[0,999]]},{"key":0,"value":[[0,49]]}]}"#)
                .confirmed_minor_max(),
            Some(49)
        );
        // Adjacent/contiguous ranges extend the run.
        assert_eq!(
            all(r#"{"all_subaddrs":[{"key":0,"value":[[0,99],[100,149]]}]}"#).confirmed_minor_max(),
            Some(149)
        );
        // Out-of-order ranges are sorted before the walk.
        assert_eq!(
            all(r#"{"all_subaddrs":[{"key":0,"value":[[100,149],[0,99]]}]}"#).confirmed_minor_max(),
            Some(149)
        );
    }

    #[test]
    fn confirmed_minor_max_stops_at_a_gap_and_never_over_reports() {
        // [[0,99],[200,299]] leaves 100..=199 UNSCANNED. Reporting 299 would let
        // the wallet hand out an address the LWS never watches.
        assert_eq!(
            all(r#"{"all_subaddrs":[{"key":0,"value":[[0,99],[200,299]]}]}"#).confirmed_minor_max(),
            Some(99)
        );
        // A run that does not start at minor 0 confirms nothing usable.
        assert_eq!(
            all(r#"{"all_subaddrs":[{"key":0,"value":[[5,99]]}]}"#).confirmed_minor_max(),
            None
        );
        // Major 0 absent, or present with no ranges at all.
        assert_eq!(
            all(r#"{"all_subaddrs":[{"key":1,"value":[[0,99]]}]}"#).confirmed_minor_max(),
            None
        );
        assert_eq!(
            all(r#"{"all_subaddrs":[{"key":0,"value":[]}]}"#).confirmed_minor_max(),
            None
        );
        // `new_subaddrs` is never consulted: an idempotent repeat returns it
        // empty, so trusting it would silently under- or over-report.
        assert_eq!(
            all(r#"{"new_subaddrs":[{"key":0,"value":[[0,199]]}],"all_subaddrs":[]}"#)
                .confirmed_minor_max(),
            None
        );
        // An inverted range is dropped rather than trusted.
        assert_eq!(
            all(r#"{"all_subaddrs":[{"key":0,"value":[[9,1]]}]}"#).confirmed_minor_max(),
            None
        );
    }

    #[test]
    fn provision_response_rejects_a_malformed_range_entry() {
        // Strict parse: a missing/garbage major index is an error, never a
        // default that could be mistaken for major 0.
        assert!(serde_json::from_str::<ProvisionSubaddrsResponse>(
            r#"{"all_subaddrs":[{"value":[[0,199]]}]}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ProvisionSubaddrsResponse>(
            r#"{"all_subaddrs":[{"key":"nope","value":[[0,199]]}]}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ProvisionSubaddrsResponse>(
            r#"{"all_subaddrs":[{"key":0,"value":[[0]]}]}"#
        )
        .is_err());
    }

    // ── LWS capability probe ──────────────────────────────────────────────────

    #[test]
    fn version_response_reads_max_subaddresses_strictly() {
        let v: LwsVersionResponse =
            serde_json::from_str(r#"{"server_type":"monero-lws","max_subaddresses":200}"#).unwrap();
        assert_eq!(v.max_subaddresses, 200);
        // String-encoded is accepted (monero-lws stringifies some numerics).
        let s: LwsVersionResponse = serde_json::from_str(r#"{"max_subaddresses":"0"}"#).unwrap();
        assert_eq!(s.max_subaddresses, 0);
        // Absent or garbage must ERROR, never default to a capable-looking value.
        assert!(serde_json::from_str::<LwsVersionResponse>(r#"{"server_type":"x"}"#).is_err());
        assert!(
            serde_json::from_str::<LwsVersionResponse>(r#"{"max_subaddresses":null}"#).is_err()
        );
    }

    // ── spend records carry the index of the output being spent ───────────────

    #[test]
    fn spent_output_parses_the_sender_subaddress_index() {
        // monero-lws emits the spent output's own index as `sender`.
        let s: SpentOutput = serde_json::from_str(
            r#"{"amount":"7","key_image":"ki","tx_pub_key":"tp","out_index":2,"mixin":15,
                "sender":{"maj_i":0,"min_i":12}}"#,
        )
        .unwrap();
        assert_eq!(
            s.sender,
            SubaddrIndex {
                maj_i: 0,
                min_i: 12
            }
        );
        assert_eq!(s.amount, 7);
    }

    #[test]
    fn spent_output_without_an_index_still_parses_as_primary() {
        // A pre-subaddress LWS omits the field entirely; the response must still
        // parse (money gate G2) and read as the primary index.
        let s: SpentOutput = serde_json::from_str(
            r#"{"amount":"7","key_image":"ki","tx_pub_key":"tp","out_index":2,"mixin":15}"#,
        )
        .unwrap();
        assert_eq!(s.sender, SubaddrIndex::default());
        // `recipient` is accepted as an alias.
        let aliased: SpentOutput = serde_json::from_str(
            r#"{"amount":"7","key_image":"ki","tx_pub_key":"tp","recipient":{"maj_i":0,"min_i":4}}"#,
        )
        .unwrap();
        assert_eq!(aliased.sender, SubaddrIndex { maj_i: 0, min_i: 4 });
    }

    #[test]
    fn tx_spend_index_is_independent_of_the_enclosing_tx_recipient() {
        // The tx-level `recipient` is the CHANGE index; the spend's own index is
        // what recomputes the key image. They must not be conflated.
        let json = r#"{
            "transactions": [{
                "hash": "h1",
                "height": 10,
                "total_received": "5",
                "recipient": {"maj_i": 0, "min_i": 1},
                "spent_outputs": [
                    {"amount":"9","key_image":"ki","tx_pub_key":"tp","sender":{"maj_i":0,"min_i":7}}
                ]
            }]
        }"#;
        let resp: AddressTxsResponse = serde_json::from_str(json).unwrap();
        let tx = &resp.transactions[0];
        assert_eq!(tx.recipient, SubaddrIndex { maj_i: 0, min_i: 1 });
        assert_eq!(
            tx.spent_outputs[0].sender,
            SubaddrIndex { maj_i: 0, min_i: 7 }
        );
    }
}
