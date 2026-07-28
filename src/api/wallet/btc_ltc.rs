//! Bitcoin/Litecoin wallet handlers — thin authenticated proxies over the
//! [`ElectrumClient`](crate::infra::electrum::ElectrumClient).
//!
//! The backend is non-custodial: it holds no keys. The wallet derives addresses
//! and signs transactions locally; these endpoints only relay reads
//! (balance/UTXOs/history/tip/fee) and a finalized broadcast to Electrum/Fulcrum.
//!
//! Conventions (matching [`crate::api::users`]):
//! * JWT-gated: every endpoint resolves the caller via
//!   [`extract_user_id_from_token`] purely to gate abuse — the queried address is
//!   client-supplied and is NOT persisted against the user (no address↔identity
//!   graph is stored here).
//! * `asset` crosses the wire as a lowercase string (`"btc"`/`"ltc"`); a disabled
//!   or unknown asset is a 400. The Electrum client validates the address (and its
//!   network) before any network call.
//! * snake_case wire fields; every DTO derives `utoipa::ToSchema`.
//! * Routes are RELATIVE to the `/api/v1` mount point; see [`routes`].

use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::api::middleware::extract_user_id_from_token;
use crate::error::AppError;
use crate::infra::electrum::{BatchError, ElectrumClient};
use crate::AppState;

/// Generous cap on a raw transaction hex (~100 KB of tx). Bounds the broadcast
/// body before it reaches the node; the axum body limit is a second backstop.
const MAX_TX_HEX_LEN: usize = 200_000;

/// HARD cap on the number of addresses in one batch (`*_multi`) request. Mirrors
/// the fixed-ceiling discipline of [`MAX_TX_HEX_LEN`]: a client-supplied length
/// is bounded before any network fan-out so one request cannot fan out
/// unboundedly. A wallet with more addresses batches in groups of this size.
const MAX_MULTI_ADDRESSES: usize = 32;

/// Dark feature flag (default OFF): the additive batch (`*_multi`) endpoints are
/// only mounted when `FEATURE_UTXO_MULTI_ADDRESS` is set truthy in the
/// environment. OFF ⇒ the routes do not exist (404) and every existing
/// single-address endpoint is byte-for-byte unchanged. Kept as an environment
/// read (not a new `Config` field) to stay within this change's file lane.
pub(crate) fn utxo_multi_enabled() -> bool {
    crate::api::capabilities::env_flag_enabled("FEATURE_UTXO_MULTI_ADDRESS")
}

/// HTTP mapping for a batch query outcome.
///
/// [`BatchError::Deadline`] is its own status (504) rather than the generic
/// upstream-unavailable 503: a batch that ran out of time is not a broken node,
/// and a wallet should back off and re-batch smaller rather than mark the chain
/// down. Everything else delegates to the shared [`AppError`] mapping, so the
/// error envelope (`{error, code}`) and the CWE-209 redaction rules are
/// unchanged.
impl axum::response::IntoResponse for BatchError {
    fn into_response(self) -> axum::response::Response {
        match self {
            BatchError::App(e) => e.into_response(),
            BatchError::Deadline => (
                axum::http::StatusCode::GATEWAY_TIMEOUT,
                axum::Json(serde_json::json!({
                    "error": "Batch address query timed out",
                    "code": "BATCH_TIMEOUT",
                })),
            )
                .into_response(),
        }
    }
}

/// Bound a batch address list: non-empty and within [`MAX_MULTI_ADDRESSES`].
/// Rejects (never truncates) an oversized list so the caller's intent is never
/// silently narrowed.
fn validate_address_batch(addresses: &[String]) -> Result<(), AppError> {
    if addresses.is_empty() {
        return Err(AppError::ValidationError(
            "addresses must not be empty".into(),
        ));
    }
    if addresses.len() > MAX_MULTI_ADDRESSES {
        return Err(AppError::ValidationError(format!(
            "too many addresses (max {MAX_MULTI_ADDRESSES})"
        )));
    }
    Ok(())
}

/// Resolve the Electrum client for a UTXO asset, or a 400 (unknown / disabled).
fn electrum_for<'a>(state: &'a AppState, asset: &str) -> Result<&'a ElectrumClient, AppError> {
    let client = match asset {
        "btc" => state.chains.btc.as_ref(),
        "ltc" => state.chains.ltc.as_ref(),
        other => {
            return Err(AppError::ValidationError(format!(
                "Invalid UTXO asset: {other} (expected btc or ltc)"
            )))
        }
    };
    client.ok_or_else(|| {
        AppError::ValidationError(format!("{asset} support is not enabled on this server"))
    })
}

/// Validate a broadcast payload: non-empty, even-length, hex, within the cap.
fn validate_tx_hex(tx_hex: &str) -> Result<(), AppError> {
    if tx_hex.is_empty() || tx_hex.len() > MAX_TX_HEX_LEN {
        return Err(AppError::ValidationError(
            "Transaction hex has invalid length".into(),
        ));
    }
    if !tx_hex.len().is_multiple_of(2) || !tx_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::ValidationError(
            "Transaction must be even-length hexadecimal".into(),
        ));
    }
    Ok(())
}

// ── DTOs ────────────────────────────────────────────────────────────────────

/// An address query for a UTXO asset.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AddressRequest {
    /// `btc` or `ltc`.
    pub asset: String,
    /// The address to query (validated by the Electrum client).
    pub address: String,
}

/// Confirmed/unconfirmed balance in satoshis. The client computes any total
/// (kept as separate integer fields — no lossy server-side sum).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BalanceResponse {
    pub asset: String,
    pub address: String,
    pub confirmed: u64,
    pub unconfirmed: i64,
}

/// A single unspent output.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Utxo {
    pub txid: String,
    pub vout: u64,
    pub value: u64,
    /// Block height; `0` if unconfirmed.
    pub height: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UtxosResponse {
    pub asset: String,
    pub address: String,
    pub utxos: Vec<Utxo>,
}

/// A transaction-history entry.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HistoryEntry {
    pub txid: String,
    /// Block height (`0`/negative for unconfirmed).
    pub height: i64,
    /// Fee in satoshis (mempool entries only).
    pub fee: Option<u64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HistoryResponse {
    pub asset: String,
    pub address: String,
    pub transactions: Vec<HistoryEntry>,
}

/// A batch query for several addresses of one UTXO asset. The list is bounded
/// server-side (see [`MAX_MULTI_ADDRESSES`]).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct MultiAddressRequest {
    /// `btc` or `ltc`.
    pub asset: String,
    /// The addresses to query (each validated by the Electrum client).
    pub addresses: Vec<String>,
}

/// Confirmed/unconfirmed balance summed across the requested addresses. Summed
/// with checked arithmetic server-side (a hostile value errors, never wraps);
/// the wallet computes any grand total from these integer fields.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MultiBalanceResponse {
    pub asset: String,
    pub confirmed: u64,
    pub unconfirmed: i64,
}

/// A single unspent output TAGGED with the address it belongs to. The tag is
/// load-bearing: the wallet never re-derives which address owns a UTXO.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TaggedUtxo {
    pub address: String,
    pub txid: String,
    pub vout: u64,
    pub value: u64,
    /// Block height; `0` if unconfirmed.
    pub height: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MultiUtxosResponse {
    pub asset: String,
    pub utxos: Vec<TaggedUtxo>,
}

/// A transaction-history entry TAGGED with its owning address.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TaggedHistoryEntry {
    pub address: String,
    pub txid: String,
    /// Block height (`0`/negative for unconfirmed).
    pub height: i64,
    /// Fee in satoshis (mempool entries only).
    pub fee: Option<u64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MultiHistoryResponse {
    pub asset: String,
    pub transactions: Vec<TaggedHistoryEntry>,
}

/// An asset-only query.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssetRequest {
    /// `btc` or `ltc`.
    pub asset: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TipResponse {
    pub asset: String,
    /// Best-chain tip height.
    pub height: i64,
}

/// A fee-estimate request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FeeRequest {
    /// `btc` or `ltc`.
    pub asset: String,
    /// Target confirmation within this many blocks.
    pub blocks: u32,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FeeResponse {
    pub asset: String,
    /// Estimated fee rate in sat/vB, or `null` if the server can't estimate.
    pub sat_per_vb: Option<f64>,
}

/// A broadcast request: a finalized, signed raw transaction.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BroadcastRequest {
    /// `btc` or `ltc`.
    pub asset: String,
    /// Hex-encoded signed transaction.
    pub tx_hex: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BroadcastResponse {
    /// The broadcast transaction id.
    pub txid: String,
}

// ── handlers ──────────────────────────────────────────────────────────────────

/// Confirmed/unconfirmed balance for a BTC/LTC address.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/utxo/balance",
    request_body = AddressRequest,
    responses(
        (status = 200, description = "Address balance in satoshis", body = BalanceResponse),
        (status = 400, description = "Invalid/disabled asset or address"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "btc_ltc"
)]
#[instrument(skip(state, headers, req))]
pub async fn balance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AddressRequest>,
) -> Result<Json<BalanceResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let bal = electrum_for(&state, &asset)?
        .get_balance(&req.address)
        .await?;
    Ok(Json(BalanceResponse {
        asset,
        address: req.address,
        confirmed: bal.confirmed,
        unconfirmed: bal.unconfirmed,
    }))
}

/// Unspent outputs for a BTC/LTC address.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/utxo/utxos",
    request_body = AddressRequest,
    responses(
        (status = 200, description = "Unspent outputs", body = UtxosResponse),
        (status = 400, description = "Invalid/disabled asset or address"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "btc_ltc"
)]
#[instrument(skip(state, headers, req))]
pub async fn utxos(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AddressRequest>,
) -> Result<Json<UtxosResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let utxos = electrum_for(&state, &asset)?
        .get_utxos(&req.address)
        .await?;
    Ok(Json(UtxosResponse {
        asset,
        address: req.address,
        utxos: utxos
            .into_iter()
            .map(|u| Utxo {
                txid: u.tx_hash,
                vout: u.tx_pos,
                value: u.value,
                height: u.height,
            })
            .collect(),
    }))
}

/// Confirmed + mempool transaction history for a BTC/LTC address.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/utxo/history",
    request_body = AddressRequest,
    responses(
        (status = 200, description = "Transaction history", body = HistoryResponse),
        (status = 400, description = "Invalid/disabled asset or address"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "btc_ltc"
)]
#[instrument(skip(state, headers, req))]
pub async fn history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AddressRequest>,
) -> Result<Json<HistoryResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let entries = electrum_for(&state, &asset)?
        .get_history(&req.address)
        .await?;
    Ok(Json(HistoryResponse {
        asset,
        address: req.address,
        transactions: entries
            .into_iter()
            .map(|e| HistoryEntry {
                txid: e.tx_hash,
                height: e.height,
                fee: e.fee,
            })
            .collect(),
    }))
}

/// Best-chain tip height (for client-side confirmation counting).
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/utxo/tip",
    request_body = AssetRequest,
    responses(
        (status = 200, description = "Chain tip height", body = TipResponse),
        (status = 400, description = "Invalid/disabled asset"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "btc_ltc"
)]
#[instrument(skip(state, headers, req))]
pub async fn tip(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AssetRequest>,
) -> Result<Json<TipResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let height = electrum_for(&state, &asset)?.get_tip_height().await?;
    Ok(Json(TipResponse { asset, height }))
}

/// Fee-rate estimate (sat/vB) for confirmation within `blocks` blocks.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/utxo/fee",
    request_body = FeeRequest,
    responses(
        (status = 200, description = "Fee estimate", body = FeeResponse),
        (status = 400, description = "Invalid/disabled asset"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "btc_ltc"
)]
#[instrument(skip(state, headers, req))]
pub async fn fee(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<FeeRequest>,
) -> Result<Json<FeeResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let sat_per_vb = electrum_for(&state, &asset)?
        .estimate_fee(req.blocks)
        .await?;
    Ok(Json(FeeResponse { asset, sat_per_vb }))
}

/// Broadcast a finalized, signed BTC/LTC transaction.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/utxo/broadcast",
    request_body = BroadcastRequest,
    responses(
        (status = 200, description = "Broadcast accepted; returns the txid", body = BroadcastResponse),
        (status = 400, description = "Invalid/disabled asset or malformed tx hex"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "btc_ltc"
)]
#[instrument(skip(state, headers, req))]
pub async fn broadcast(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BroadcastRequest>,
) -> Result<Json<BroadcastResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    let client = electrum_for(&state, &asset)?;
    validate_tx_hex(&req.tx_hex)?;
    let txid = client.broadcast_transaction(&req.tx_hex).await?;
    Ok(Json(BroadcastResponse { txid }))
}

// ── batch (multi-address) handlers ────────────────────────────────────────────

/// Confirmed/unconfirmed balance summed across a batch of BTC/LTC addresses.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/utxo/balance_multi",
    request_body = MultiAddressRequest,
    responses(
        (status = 200, description = "Summed balance in satoshis", body = MultiBalanceResponse),
        (status = 400, description = "Invalid/disabled asset, address, or oversized batch"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable"),
        (status = 504, description = "The batch exceeded its deadline; retry with a smaller batch")
    ),
    tag = "btc_ltc"
)]
#[instrument(skip(state, headers, req))]
pub async fn balance_multi(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<MultiAddressRequest>,
) -> Result<Json<MultiBalanceResponse>, BatchError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    validate_address_batch(&req.addresses)?;
    let bal = electrum_for(&state, &asset)?
        .get_balance_sum(&req.addresses)
        .await?;
    Ok(Json(MultiBalanceResponse {
        asset,
        confirmed: bal.confirmed,
        unconfirmed: bal.unconfirmed,
    }))
}

/// Unspent outputs across a batch of BTC/LTC addresses, each tagged with its
/// owning address (the wallet never re-guesses UTXO ownership).
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/utxo/utxos_multi",
    request_body = MultiAddressRequest,
    responses(
        (status = 200, description = "Address-tagged unspent outputs", body = MultiUtxosResponse),
        (status = 400, description = "Invalid/disabled asset, address, or oversized batch"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable"),
        (status = 504, description = "The batch exceeded its deadline; retry with a smaller batch")
    ),
    tag = "btc_ltc"
)]
#[instrument(skip(state, headers, req))]
pub async fn utxos_multi(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<MultiAddressRequest>,
) -> Result<Json<MultiUtxosResponse>, BatchError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    validate_address_batch(&req.addresses)?;
    let tagged = electrum_for(&state, &asset)?
        .get_utxos_tagged(&req.addresses)
        .await?;
    Ok(Json(MultiUtxosResponse {
        asset,
        utxos: tagged
            .into_iter()
            .map(|(address, u)| TaggedUtxo {
                address,
                txid: u.tx_hash,
                vout: u.tx_pos,
                value: u.value,
                height: u.height,
            })
            .collect(),
    }))
}

/// Confirmed + mempool history across a batch of BTC/LTC addresses, each entry
/// tagged with its owning address.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/utxo/history_multi",
    request_body = MultiAddressRequest,
    responses(
        (status = 200, description = "Address-tagged transaction history", body = MultiHistoryResponse),
        (status = 400, description = "Invalid/disabled asset, address, or oversized batch"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable"),
        (status = 504, description = "The batch exceeded its deadline; retry with a smaller batch")
    ),
    tag = "btc_ltc"
)]
#[instrument(skip(state, headers, req))]
pub async fn history_multi(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<MultiAddressRequest>,
) -> Result<Json<MultiHistoryResponse>, BatchError> {
    extract_user_id_from_token(&state, &headers).await?;
    let asset = req.asset.to_lowercase();
    validate_address_batch(&req.addresses)?;
    let tagged = electrum_for(&state, &asset)?
        .get_history_tagged(&req.addresses)
        .await?;
    Ok(Json(MultiHistoryResponse {
        asset,
        transactions: tagged
            .into_iter()
            .map(|(address, e)| TaggedHistoryEntry {
                address,
                txid: e.tx_hash,
                height: e.height,
                fee: e.fee,
            })
            .collect(),
    }))
}

// ── router ────────────────────────────────────────────────────────────────────

/// BTC/LTC routes, RELATIVE to the `/api/v1` mount point.
pub fn routes() -> Router<Arc<AppState>> {
    let mut router = Router::new()
        .route("/wallet/utxo/balance", post(balance))
        .route("/wallet/utxo/utxos", post(utxos))
        .route("/wallet/utxo/history", post(history))
        .route("/wallet/utxo/tip", post(tip))
        .route("/wallet/utxo/fee", post(fee))
        .route("/wallet/utxo/broadcast", post(broadcast));

    // Dark by default: the batch endpoints exist only when explicitly enabled.
    if utxo_multi_enabled() {
        router = router
            .route("/wallet/utxo/balance_multi", post(balance_multi))
            .route("/wallet/utxo/utxos_multi", post(utxos_multi))
            .route("/wallet/utxo/history_multi", post(history_multi));
    }
    router
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_hex_validation() {
        assert!(validate_tx_hex("deadbeef").is_ok());
        assert!(validate_tx_hex("DEADBEEF01").is_ok());
        assert!(validate_tx_hex("").is_err()); // empty
        assert!(validate_tx_hex("abc").is_err()); // odd length
        assert!(validate_tx_hex("xyz!").is_err()); // non-hex
        assert!(validate_tx_hex(&"a".repeat(MAX_TX_HEX_LEN + 1)).is_err()); // too long
    }

    #[test]
    fn multi_address_request_deserializes() {
        let req: MultiAddressRequest =
            serde_json::from_str(r#"{"asset":"btc","addresses":["a1","a2","a3"]}"#).unwrap();
        assert_eq!(req.asset, "btc");
        assert_eq!(req.addresses.len(), 3);
    }

    #[test]
    fn address_batch_bounds() {
        // A normal batch passes.
        assert!(validate_address_batch(&["a".into(), "b".into()]).is_ok());
        // Exactly at the cap passes.
        let at_cap: Vec<String> = (0..MAX_MULTI_ADDRESSES).map(|i| i.to_string()).collect();
        assert!(validate_address_batch(&at_cap).is_ok());
        // Empty is rejected (never a silent no-op).
        assert!(validate_address_batch(&[]).is_err());
        // Oversized is rejected (never silently truncated) — money gate G13.
        let over: Vec<String> = (0..MAX_MULTI_ADDRESSES + 1)
            .map(|i| i.to_string())
            .collect();
        assert!(validate_address_batch(&over).is_err());
    }
}
