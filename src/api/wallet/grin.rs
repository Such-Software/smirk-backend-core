//! Grin wallet handlers — authenticated, **view-only** proxies over the
//! [`GrinClient`](crate::infra::grin::GrinClient).
//!
//! The backend holds no Grin spend key. The wallet exports its `rewind_hash` (a
//! view credential derived from its *public* root key — it can recognize the
//! wallet's outputs and read amounts, but cannot spend) and sends it per scan;
//! the backend forwards it to grin-wallet's `scan_rewind_hash` and stores no
//! secret. Spending (input selection, kernel signing) happens in the wallet; the
//! backend only broadcasts the finalized transaction.
//!
//! Conventions (matching [`super::btc_ltc`] / [`super::xmr_wow`]):
//! * JWT-gated; the `rewind_hash` is a view credential — its request struct omits
//!   `Debug` and is `skip`-ped from every span, so it is never logged.
//! * snake_case wire fields; every DTO derives `utoipa::ToSchema`.
//! * Routes are RELATIVE to the `/api/v1` mount point; see [`routes`].

use std::sync::Arc;

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use super::validate_hex64;
use crate::api::middleware::extract_user_id_from_token;
use crate::error::AppError;
use crate::infra::grin::{GrinClient, ViewWalletOutputResult};
use crate::AppState;

/// Resolve the Grin client, or a 400 if Grin support is disabled.
fn grin_client(state: &AppState) -> Result<&GrinClient, AppError> {
    state.chains.grin.as_deref().ok_or_else(|| {
        AppError::ValidationError("grin support is not enabled on this server".into())
    })
}

// ── DTOs ────────────────────────────────────────────────────────────────────

/// A view-only scan request. Carries the `rewind_hash` view credential, so it
/// deliberately omits `Debug` (never logged).
#[derive(Deserialize, utoipa::ToSchema)]
pub struct GrinScanRequest {
    /// The wallet's `rewind_hash` (64 hex). Forwarded to grin-wallet; not stored.
    pub rewind_hash: String,
    /// Scan from this block height (wallet birthday / last scanned). Omit for full.
    pub start_height: Option<u64>,
}

/// A single output recovered by a view-only scan. Amounts are nanogrin.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GrinOutput {
    pub commit: String,
    pub value: u64,
    pub height: u64,
    pub mmr_index: u64,
    pub is_coinbase: bool,
    pub lock_height: u64,
}

/// Result of a view-only scan: recognized outputs, total, and the resume index.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GrinScanResponse {
    pub outputs: Vec<GrinOutput>,
    pub total_balance: u64,
    /// Resume point (`last_pmmr_index`) for the next incremental scan.
    pub last_pmmr_index: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GrinHeightResponse {
    pub height: u64,
}

/// Broadcast a finalized, signed Grin transaction (built + signed by the wallet).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct GrinBroadcastRequest {
    /// The finalized transaction object (grin node `push_transaction` input).
    #[schema(value_type = Object)]
    pub tx: serde_json::Value,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GrinBroadcastResponse {
    pub ok: bool,
}

fn output_dto(o: ViewWalletOutputResult) -> GrinOutput {
    GrinOutput {
        commit: o.commit,
        value: o.value,
        height: o.height,
        mmr_index: o.mmr_index,
        is_coinbase: o.is_coinbase,
        lock_height: o.lock_height,
    }
}

// ── handlers ──────────────────────────────────────────────────────────────────

/// View-only scan for the outputs a `rewind_hash` recognizes.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/grin/scan",
    request_body = GrinScanRequest,
    responses(
        (status = 200, description = "Recognized outputs + balance + resume index", body = GrinScanResponse),
        (status = 400, description = "Grin disabled or malformed rewind_hash"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "grin"
)]
#[instrument(skip(state, headers, req))]
pub async fn scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<GrinScanRequest>,
) -> Result<Json<GrinScanResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    validate_hex64(&req.rewind_hash, "rewind_hash")?;

    let client = grin_client(&state)?;
    if let Some(h) = req.start_height {
        // Restore: gate the scan depth against this instance's policy.
        let tip = client.get_height().await?;
        state.config.restore.enforce("grin", h, tip)?;
    }
    let view = client
        .scan_rewind_hash(&req.rewind_hash, req.start_height)
        .await?;
    Ok(Json(GrinScanResponse {
        outputs: view.output_result.into_iter().map(output_dto).collect(),
        total_balance: view.total_balance,
        last_pmmr_index: view.last_pmmr_index,
    }))
}

/// Current Grin chain tip height (for confirmation counting).
#[utoipa::path(
    security(("bearer_auth" = [])),
    get,
    path = "/wallet/grin/height",
    responses(
        (status = 200, description = "Chain tip height", body = GrinHeightResponse),
        (status = 400, description = "Grin disabled"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "grin"
)]
#[instrument(skip(state, headers))]
pub async fn height(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<GrinHeightResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    let height = grin_client(&state)?.get_height().await?;
    Ok(Json(GrinHeightResponse { height }))
}

/// Broadcast a finalized, signed Grin transaction.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/wallet/grin/broadcast",
    request_body = GrinBroadcastRequest,
    responses(
        (status = 200, description = "Transaction broadcast", body = GrinBroadcastResponse),
        (status = 400, description = "Grin disabled or malformed transaction"),
        (status = 401, description = "Missing or invalid token"),
        (status = 503, description = "Upstream node unavailable")
    ),
    tag = "grin"
)]
#[instrument(skip(state, headers, req))]
pub async fn broadcast(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<GrinBroadcastRequest>,
) -> Result<Json<GrinBroadcastResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;
    grin_client(&state)?.broadcast(&req.tx).await?;
    Ok(Json(GrinBroadcastResponse { ok: true }))
}

// ── router ────────────────────────────────────────────────────────────────────

/// Grin routes, RELATIVE to the `/api/v1` mount point.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/wallet/grin/scan", post(scan))
        .route("/wallet/grin/height", get(height))
        .route("/wallet/grin/broadcast", post(broadcast))
}
