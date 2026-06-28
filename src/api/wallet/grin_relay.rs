//! Grin slatepack relay — an async, non-custodial store-and-forward mailbox for
//! interactive Grin transfers between two registered Smirk users.
//!
//! Grin transactions are interactive: the sender's partial slate must reach the
//! recipient, who adds their output + partial signature and returns it, after
//! which the sender finalizes and broadcasts. This relay makes that asynchronous:
//! the sender posts an (encrypted) slatepack addressed to a recipient; the
//! recipient fetches and responds when online; the sender polls for the response,
//! finalizes and broadcasts LOCALLY (via `/wallet/grin/broadcast`), then records
//! the txid here.
//!
//! Non-custodial by construction: the relay stores only opaque slatepack text
//! (slatepacks are encrypted to the recipient's address) and lifecycle status. It
//! never holds keys, never finalizes, never broadcasts. The wallet finalizes and
//! broadcasts locally; the relay is only a store-and-forward mailbox.
//!
//! Controls: JWT-gated; every action authorizes the caller as the slate's sender
//! or recipient (a non-party gets 404, never an existence oracle); the recipient
//! must be a registered user (no blind spam to arbitrary addresses); slatepack
//! sizes are capped; entries expire; and the whole feature is behind
//! `FEATURE_GRIN_RELAY` so an operator can disable the mailbox.

use std::sync::Arc;

use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::api::middleware::extract_user_id_from_token;
use crate::error::AppError;
use crate::models::db::{GrinSlatepack, NewGrinSlatepack, SlatepackStatus};
use crate::AppState;

/// Cap on an armored slatepack (sender payload or recipient response). Real
/// slatepacks are a few KB; this is a generous bound against storage abuse.
const MAX_SLATEPACK_LEN: usize = 64 * 1024;
/// How long a relay entry lives before it expires.
const RELAY_TTL_DAYS: i64 = 7;

/// 400 unless the relay feature is enabled on this server.
fn ensure_enabled(state: &AppState) -> Result<(), AppError> {
    if state.config.features.grin_relay {
        Ok(())
    } else {
        Err(AppError::NotFound(
            "grin relay is not enabled on this server".into(),
        ))
    }
}

/// Which party an action requires the caller to be.
enum Party {
    Sender,
    Recipient,
    Either,
}

/// Fetch a relay by slate id and authorize the caller as the required party. A
/// non-party (or unknown slate) gets `NotFound` — "not yours" is indistinguishable
/// from "doesn't exist", so the endpoint is not an existence oracle.
async fn fetch_authorized(
    state: &AppState,
    slate_id: &str,
    user_id: Uuid,
    party: Party,
) -> Result<GrinSlatepack, AppError> {
    let row = state
        .db
        .get_slatepack_by_slate_id(slate_id)
        .await?
        .ok_or_else(|| AppError::NotFound("relay not found".into()))?;
    let is_sender = row.sender_user_id == user_id;
    let is_recipient = row.recipient_user_id == Some(user_id);
    let authorized = match party {
        Party::Sender => is_sender,
        Party::Recipient => is_recipient,
        Party::Either => is_sender || is_recipient,
    };
    if authorized {
        Ok(row)
    } else {
        Err(AppError::NotFound("relay not found".into()))
    }
}

fn status_str(status: SlatepackStatus) -> &'static str {
    match status {
        SlatepackStatus::PendingRecipient => "pending_recipient",
        SlatepackStatus::PendingSender => "pending_sender",
        SlatepackStatus::Finalized => "finalized",
        SlatepackStatus::Expired => "expired",
        SlatepackStatus::Cancelled => "cancelled",
    }
}

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339()
}

// ── DTOs ────────────────────────────────────────────────────────────────────

/// Create a relay: post an (encrypted) slatepack addressed to a registered user.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateRelayRequest {
    /// Recipient (a registered Smirk user id).
    pub recipient_user_id: Uuid,
    /// The Grin slate id (the transaction's slate UUID).
    pub slate_id: String,
    /// The armored slatepack (encrypted to the recipient).
    pub slatepack: String,
    /// Amount in nanogrin (informational; the real amount is in the slate).
    pub amount_nanogrin: i64,
}

/// The recipient's response to a pending relay.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RespondRelayRequest {
    pub slate_id: String,
    /// The armored response slatepack (recipient's partial signature added).
    pub response_slatepack: String,
}

/// Record that the sender finalized + broadcast the transaction.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FinalizeRelayRequest {
    pub slate_id: String,
    /// The broadcast transaction hash/kernel (recorded for reference).
    pub tx_hash: String,
}

/// Identify a relay by its slate id (poll / cancel).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SlateIdRequest {
    pub slate_id: String,
}

/// A relay entry as returned to an authorized party.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RelayEntry {
    pub slate_id: String,
    pub sender_user_id: String,
    pub recipient_user_id: Option<String>,
    /// The sender's armored slatepack (what the recipient responds to).
    pub slatepack_content: String,
    /// The recipient's response slatepack, once provided.
    pub response_slatepack: Option<String>,
    pub amount_nanogrin: i64,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
    pub finalized_at: Option<String>,
    pub tx_hash: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PendingRelaysResponse {
    pub relays: Vec<RelayEntry>,
}

fn relay_entry(s: GrinSlatepack) -> RelayEntry {
    RelayEntry {
        slate_id: s.slate_id,
        sender_user_id: s.sender_user_id.to_string(),
        recipient_user_id: s.recipient_user_id.map(|id| id.to_string()),
        slatepack_content: s.slatepack_content,
        response_slatepack: s.response_slatepack,
        amount_nanogrin: s.amount_nanogrin,
        status: status_str(s.status).to_string(),
        created_at: ts(s.created_at),
        expires_at: ts(s.expires_at),
        finalized_at: s.finalized_at.map(ts),
        tx_hash: s.tx_hash,
    }
}

fn validate_slate_id(slate_id: &str) -> Result<(), AppError> {
    // Grin slate ids are UUIDs; requiring that bounds the value and avoids
    // arbitrary client-chosen keys for the (now-UNIQUE) slate_id column.
    Uuid::parse_str(slate_id)
        .map(|_| ())
        .map_err(|_| AppError::ValidationError("slate_id must be a valid UUID".into()))
}

fn validate_slatepack(value: &str, field: &str) -> Result<(), AppError> {
    if value.is_empty() || value.len() > MAX_SLATEPACK_LEN {
        return Err(AppError::ValidationError(format!(
            "{field} has invalid length"
        )));
    }
    Ok(())
}

// ── handlers ──────────────────────────────────────────────────────────────────

/// Post a slatepack addressed to a registered recipient (sender = caller).
#[utoipa::path(
    post,
    path = "/wallet/grin/relay/create",
    request_body = CreateRelayRequest,
    responses(
        (status = 200, description = "Relay created (PendingRecipient)", body = RelayEntry),
        (status = 400, description = "Invalid input or unregistered recipient"),
        (status = 401, description = "Missing or invalid token"),
        (status = 404, description = "Relay feature disabled")
    ),
    tag = "grin_relay"
)]
#[instrument(skip(state, headers, req))]
pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateRelayRequest>,
) -> Result<Json<RelayEntry>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_enabled(&state)?;
    validate_slate_id(&req.slate_id)?;
    validate_slatepack(&req.slatepack, "slatepack")?;
    if req.amount_nanogrin < 0 {
        return Err(AppError::ValidationError(
            "amount_nanogrin must be non-negative".into(),
        ));
    }

    // Anti-spam: the recipient must be a registered user.
    let recipient = state
        .db
        .get_user_by_id(req.recipient_user_id)
        .await?
        .ok_or_else(|| AppError::ValidationError("recipient is not a registered user".into()))?;

    let row = state
        .db
        .create_grin_slatepack(NewGrinSlatepack {
            slate_id: req.slate_id,
            sender_user_id: user_id,
            recipient_user_id: Some(recipient.id),
            recipient_address: None,
            slatepack_content: req.slatepack,
            amount_nanogrin: req.amount_nanogrin,
            expires_at: Utc::now() + Duration::days(RELAY_TTL_DAYS),
        })
        .await?;
    Ok(Json(relay_entry(row)))
}

/// The caller's inbox: relays awaiting their response.
#[utoipa::path(
    get,
    path = "/wallet/grin/relay/pending",
    responses(
        (status = 200, description = "Relays awaiting the caller's response", body = PendingRelaysResponse),
        (status = 401, description = "Missing or invalid token"),
        (status = 404, description = "Relay feature disabled")
    ),
    tag = "grin_relay"
)]
#[instrument(skip(state, headers))]
pub async fn pending(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<PendingRelaysResponse>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_enabled(&state)?;
    let rows = state.db.get_pending_slatepacks_for_user(user_id).await?;
    Ok(Json(PendingRelaysResponse {
        relays: rows.into_iter().map(relay_entry).collect(),
    }))
}

/// Poll a relay's current state (sender or recipient). The sender uses this to
/// fetch the recipient's response once status is `pending_sender`.
#[utoipa::path(
    post,
    path = "/wallet/grin/relay/get",
    request_body = SlateIdRequest,
    responses(
        (status = 200, description = "The relay entry", body = RelayEntry),
        (status = 401, description = "Missing or invalid token"),
        (status = 404, description = "Relay not found, not yours, or feature disabled")
    ),
    tag = "grin_relay"
)]
#[instrument(skip(state, headers, req))]
pub async fn get_relay(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SlateIdRequest>,
) -> Result<Json<RelayEntry>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_enabled(&state)?;
    let row = fetch_authorized(&state, &req.slate_id, user_id, Party::Either).await?;
    Ok(Json(relay_entry(row)))
}

/// Attach the recipient's response, advancing to `pending_sender`.
#[utoipa::path(
    post,
    path = "/wallet/grin/relay/respond",
    request_body = RespondRelayRequest,
    responses(
        (status = 200, description = "Response stored (PendingSender)", body = RelayEntry),
        (status = 400, description = "Invalid response slatepack"),
        (status = 401, description = "Missing or invalid token"),
        (status = 404, description = "Relay not found, not yours, or feature disabled"),
        (status = 409, description = "Relay is not awaiting a recipient response")
    ),
    tag = "grin_relay"
)]
#[instrument(skip(state, headers, req))]
pub async fn respond(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RespondRelayRequest>,
) -> Result<Json<RelayEntry>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_enabled(&state)?;
    validate_slatepack(&req.response_slatepack, "response_slatepack")?;
    let row = fetch_authorized(&state, &req.slate_id, user_id, Party::Recipient).await?;
    // The status + expiry guard is atomic in the UPDATE (keyed on row.id); a
    // non-qualifying row returns None -> 409.
    let updated = state
        .db
        .add_slatepack_response(row.id, &req.response_slatepack)
        .await?
        .ok_or_else(|| {
            AppError::Conflict("relay is not awaiting a recipient response (or has expired)".into())
        })?;
    Ok(Json(relay_entry(updated)))
}

/// Record that the sender finalized + broadcast the transaction (sender only).
/// The backend does NOT finalize or broadcast — the wallet does that locally and
/// reports the resulting tx hash here.
#[utoipa::path(
    post,
    path = "/wallet/grin/relay/finalize",
    request_body = FinalizeRelayRequest,
    responses(
        (status = 200, description = "Relay marked finalized", body = RelayEntry),
        (status = 400, description = "Invalid tx hash"),
        (status = 401, description = "Missing or invalid token"),
        (status = 404, description = "Relay not found, not yours, or feature disabled"),
        (status = 409, description = "Relay is not awaiting finalization")
    ),
    tag = "grin_relay"
)]
#[instrument(skip(state, headers, req))]
pub async fn finalize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<FinalizeRelayRequest>,
) -> Result<Json<RelayEntry>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_enabled(&state)?;
    if req.tx_hash.is_empty() || req.tx_hash.len() > 128 {
        return Err(AppError::ValidationError(
            "tx_hash has invalid length".into(),
        ));
    }
    let row = fetch_authorized(&state, &req.slate_id, user_id, Party::Sender).await?;
    let updated = state
        .db
        .finalize_slatepack(row.id, &req.tx_hash)
        .await?
        .ok_or_else(|| {
            AppError::Conflict("relay is not awaiting finalization (or has expired)".into())
        })?;
    Ok(Json(relay_entry(updated)))
}

/// Cancel a relay (sender or recipient), unless already finalized.
#[utoipa::path(
    post,
    path = "/wallet/grin/relay/cancel",
    request_body = SlateIdRequest,
    responses(
        (status = 200, description = "Relay cancelled", body = RelayEntry),
        (status = 401, description = "Missing or invalid token"),
        (status = 404, description = "Relay not found, not yours, or feature disabled"),
        (status = 409, description = "Relay is already finalized")
    ),
    tag = "grin_relay"
)]
#[instrument(skip(state, headers, req))]
pub async fn cancel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SlateIdRequest>,
) -> Result<Json<RelayEntry>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    ensure_enabled(&state)?;
    let row = fetch_authorized(&state, &req.slate_id, user_id, Party::Either).await?;
    let updated = state.db.cancel_slatepack(row.id).await?.ok_or_else(|| {
        AppError::Conflict(
            "relay can no longer be cancelled (already finalized or cancelled)".into(),
        )
    })?;
    Ok(Json(relay_entry(updated)))
}

// ── router ────────────────────────────────────────────────────────────────────

/// Grin relay routes, RELATIVE to the `/api/v1` mount point.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/wallet/grin/relay/create", post(create))
        .route("/wallet/grin/relay/pending", get(pending))
        .route("/wallet/grin/relay/get", post(get_relay))
        .route("/wallet/grin/relay/respond", post(respond))
        .route("/wallet/grin/relay/finalize", post(finalize))
        .route("/wallet/grin/relay/cancel", post(cancel))
}
