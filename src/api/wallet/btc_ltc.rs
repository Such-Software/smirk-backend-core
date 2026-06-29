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
use crate::infra::electrum::ElectrumClient;
use crate::AppState;

/// Generous cap on a raw transaction hex (~100 KB of tx). Bounds the broadcast
/// body before it reaches the node; the axum body limit is a second backstop.
const MAX_TX_HEX_LEN: usize = 200_000;

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

// ── router ────────────────────────────────────────────────────────────────────

/// BTC/LTC routes, RELATIVE to the `/api/v1` mount point.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/wallet/utxo/balance", post(balance))
        .route("/wallet/utxo/utxos", post(utxos))
        .route("/wallet/utxo/history", post(history))
        .route("/wallet/utxo/tip", post(tip))
        .route("/wallet/utxo/fee", post(fee))
        .route("/wallet/utxo/broadcast", post(broadcast))
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
}
