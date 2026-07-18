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
    extract::{Path, State},
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
use crate::infra::grin_lws::{GrinLwsClient, GrinLwsUnspentOut};
use crate::AppState;

/// Blocks grin-lws's per-account scan may lag the chain tip and still be trusted.
/// Beyond this margin the account is treated as not-yet-synced and the scan falls
/// back to the authoritative grin-wallet scan — the money-safety seam.
const SYNC_MARGIN: u64 = 2;

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
    /// Restore proof-of-work nonce. Required when the instance prices the
    /// requested restore depth (see `/capabilities` → `restore.pow_*`); bound to
    /// `(grin, rewind_hash, start_height)` (see `restore_pow`).
    #[serde(default)]
    pub restore_pow_nonce: Option<u64>,
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
    /// Recovered derivation key id — populated only on the grin-lws path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Recovered child index — populated only on the grin-lws path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n_child: Option<u32>,
    /// Spendable at the current tip — populated only on the grin-lws path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spendable: Option<bool>,
}

/// Result of a view-only scan: recognized outputs, total, and the resume index.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GrinScanResponse {
    pub outputs: Vec<GrinOutput>,
    pub total_balance: u64,
    /// Resume point (`last_pmmr_index`) for the next incremental scan.
    pub last_pmmr_index: u64,
    /// How far grin-lws has scanned this account — present only on the grin-lws
    /// path (the authoritative grin-wallet path leaves it null).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_height: Option<u64>,
    /// Chain tip observed by grin-lws at scan time — present only on the grin-lws
    /// path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockchain_height: Option<u64>,
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

/// Resolution of a bare Grin address to its owning user's routing identity.
///
/// The address→npub **bridge**: given a `grin1…` slatepack address, report
/// whether it belongs to a user registered on *this* backend and, if so, that
/// user's linked Nostr pubkey so a bare-address send can be upgraded to a
/// federated Nostr gift-wrap instead of the same-instance relay.
///
/// NOTE (federation): this is a **same-instance convenience**. It can only
/// resolve addresses whose owner registered their Grin key here (via `POST
/// /keys`). It is *not* a federated directory — a wallet on another backend
/// won't be found. `registered: false` (a constant-shape miss, mirroring
/// `GET /users/by-username`) means "unknown to this instance", at which point
/// the sender falls back to manual clipboard / the backend relay.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GrinAddressUserResponse {
    /// Whether the address resolved to a user on this backend.
    pub registered: bool,
    /// The owning user's id (UUID), when `registered`.
    pub user_id: Option<String>,
    /// The owning user's linked Nostr pubkey (x-only hex), when they have one.
    /// This is what the sender feeds the Nostr gift-wrap channel to route the
    /// slate over Nostr. `None` when the user registered no Nostr identity.
    pub npub: Option<String>,
}

fn output_dto(o: ViewWalletOutputResult) -> GrinOutput {
    GrinOutput {
        commit: o.commit,
        value: o.value,
        height: o.height,
        mmr_index: o.mmr_index,
        is_coinbase: o.is_coinbase,
        lock_height: o.lock_height,
        // The grin-wallet scan does not surface derivation paths / spendability.
        key_id: None,
        n_child: None,
        spendable: None,
    }
}

/// Map a grin-lws unspent output (which carries the recovered derivation path and
/// spendability) into the wire DTO.
fn output_dto_lws(o: GrinLwsUnspentOut) -> GrinOutput {
    GrinOutput {
        commit: o.commit,
        value: o.value,
        height: o.height,
        mmr_index: o.mmr_index,
        is_coinbase: o.is_coinbase,
        lock_height: o.lock_height,
        key_id: o.key_id,
        n_child: o.n_child,
        spendable: Some(o.spendable),
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

    // Restore-depth + PoW gate runs ONCE, before path selection, and is TERMINAL:
    // a policy rejection returns 400 directly. It must never be masked by the
    // grin-wallet fallback, so it is enforced before either scan path is chosen.
    if let Some(h) = req.start_height {
        let tip = grin_tip(&state).await?;
        state.cfg().restore.enforce("grin", h, tip)?;
        state.cfg().restore.enforce_restore_pow(
            "grin",
            &req.rewind_hash,
            h,
            tip,
            req.restore_pow_nonce,
        )?;
    }

    // Default to grin-lws when configured. It is trusted ONLY when provably synced
    // to the tip; otherwise (and on any transport error) the scan falls back to
    // the authoritative grin-wallet scan below.
    if let Some(lws) = state.chains.grin_lws.as_ref() {
        match scan_via_grin_lws(lws, &req).await {
            Ok(Some(resp)) => return Ok(Json(resp)),
            Ok(None) => {} // still backfilling — fall through to grin-wallet
            Err(e) => {
                tracing::warn!(error = %e, "grin-lws scan failed; falling back to grin-wallet")
            }
        }
    }

    // Authoritative grin-wallet scan. Its error propagates as-is (503) — we never
    // synthesize an empty/zero success.
    let client = grin_client(&state)?;
    let view = client
        .scan_rewind_hash(&req.rewind_hash, req.start_height)
        .await?;
    Ok(Json(GrinScanResponse {
        outputs: view.output_result.into_iter().map(output_dto).collect(),
        total_balance: view.total_balance,
        last_pmmr_index: view.last_pmmr_index,
        scanned_height: None,
        blockchain_height: None,
    }))
}

/// Current Grin chain tip for the restore gate: grin-lws's `/height` when
/// configured, else the authoritative grin-wallet node. A grin-lws height error
/// falls back to grin-wallet's tip so the gate can always be enforced.
async fn grin_tip(state: &AppState) -> Result<u64, AppError> {
    if let Some(lws) = state.chains.grin_lws.as_ref() {
        match lws.get_height().await {
            Ok(h) => return Ok(h),
            Err(e) => {
                tracing::warn!(error = %e, "grin-lws height failed; falling back to grin-wallet tip")
            }
        }
    }
    grin_client(state)?.get_height().await
}

/// Attempt the scan via grin-lws.
///
/// Returns `Ok(Some(resp))` only when the account is provably synced to the tip
/// (`scanned_height + SYNC_MARGIN >= blockchain_height`) — the money-safety seam.
/// `Ok(None)` means grin-lws is still backfilling this account, so the caller
/// must fall back to the authoritative grin-wallet scan. A transport error
/// propagates (the caller treats it as a fallback signal, never a 0/empty scan).
async fn scan_via_grin_lws(
    lws: &GrinLwsClient,
    req: &GrinScanRequest,
) -> Result<Option<GrinScanResponse>, AppError> {
    lws.register(&req.rewind_hash, req.start_height).await?;
    let bal = lws.get_balance(&req.rewind_hash).await?;
    // Trust grin-lws only when its scan has effectively reached the tip.
    // `saturating_add` so a hostile/garbled `scanned_height` can never overflow
    // into a spurious "synced" — the worst case just falls back to grin-wallet.
    if bal.scanned_height.saturating_add(SYNC_MARGIN) < bal.blockchain_height {
        return Ok(None);
    }
    let outs = lws.get_unspent_outs(&req.rewind_hash).await?;
    let max_mmr = outs.outputs.iter().map(|o| o.mmr_index).max().unwrap_or(0);
    let outputs = outs.outputs.into_iter().map(output_dto_lws).collect();
    Ok(Some(GrinScanResponse {
        outputs,
        total_balance: bal.total,
        last_pmmr_index: max_mmr,
        scanned_height: Some(bal.scanned_height),
        blockchain_height: Some(bal.blockchain_height),
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

/// Resolve a bare Grin address to its owning user's Nostr routing identity.
///
/// The address→npub bridge (see [`GrinAddressUserResponse`]). JWT-gated: only
/// authenticated senders resolve routing. An address unknown to this backend
/// returns the constant-shape `registered: false` response — the caller then
/// falls back to manual clipboard or the same-instance relay.
#[utoipa::path(
    security(("bearer_auth" = [])),
    get,
    path = "/wallet/grin/address/{addr}/user",
    params(("addr" = String, Path, description = "Grin address (registered public key)")),
    responses(
        (status = 200, description = "Address resolution result", body = GrinAddressUserResponse),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "grin"
)]
#[instrument(skip(state, headers))]
pub async fn address_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(addr): Path<String>,
) -> Result<Json<GrinAddressUserResponse>, AppError> {
    extract_user_id_from_token(&state, &headers).await?;

    let Some(user) = state.db.find_user_by_grin_address(&addr).await? else {
        return Ok(Json(GrinAddressUserResponse {
            registered: false,
            user_id: None,
            npub: None,
        }));
    };

    Ok(Json(GrinAddressUserResponse {
        registered: true,
        user_id: Some(user.id.to_string()),
        npub: user.nostr_pubkey,
    }))
}

// ── router ────────────────────────────────────────────────────────────────────

/// Grin routes, RELATIVE to the `/api/v1` mount point.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/wallet/grin/scan", post(scan))
        .route("/wallet/grin/height", get(height))
        .route("/wallet/grin/broadcast", post(broadcast))
        .route("/wallet/grin/address/:addr/user", get(address_user))
}
