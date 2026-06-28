//! Self-service erasure (operator §5) — the one sensitive operation reachable on
//! the public plane, so a user who no longer trusts the backend can reach in.
//!
//! Every action is gated by a fresh NIP-98 *signed action* (a session token is
//! NEVER sufficient), bound to a single-use server nonce + a canonical request
//! descriptor + (for confirm/cancel) the explicit `erasure_id`. Erasure may only
//! target the `users.id` that the proof's key resolves to (via the linked
//! `nostr_pubkey`) — a leaked identifier is never a selector. Two-phase
//! (request -> confirm) with a grace window; a background sweeper executes.
//!
//! Threat model (documented): erasure authority == key control == account
//! compromise already, so this is an operator-distrust/regret exit, not an
//! anti-theft control (key rotation is that). The grace window's value is
//! operator error/regret.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::{delete, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, instrument, warn};
use uuid::Uuid;

use crate::core::crypto::nip98::{descriptor_sha256, request_descriptor, verify_signed_action};
use crate::error::AppError;
use crate::models::db::{NewAdminAudit, User};
use crate::AppState;

const CHALLENGE_TTL_SECS: i64 = 300;
const ACTION_MAX_AGE_SECS: i64 = 30;
const PURPOSE_REQUEST: &str = "erasure_request";
const PURPOSE_CONFIRM: &str = "erasure_confirm";
const PURPOSE_CANCEL: &str = "erasure_cancel";
const PURPOSE_EXPORT: &str = "erasure_export";

// ── helpers ──────────────────────────────────────────────────────────────────

fn ensure_enabled(state: &AppState) -> Result<(), AppError> {
    if state.config.retention.erasure_enabled {
        Ok(())
    } else {
        Err(AppError::NotFound("erasure is not enabled".into()))
    }
}

/// The signed-action `u`-tag base for `path` (e.g. `/account/erasure`), from
/// `PUBLIC_API_URL` (which already includes the `/api/v1` prefix).
fn erasure_url(state: &AppState, path: &str) -> Result<String, AppError> {
    let base = state
        .config
        .identity
        .public_api_url
        .as_deref()
        .ok_or_else(|| AppError::NotFound("erasure is not enabled".into()))?;
    Ok(format!("{}{}", base.trim_end_matches('/'), path))
}

fn subject_hash(npub: &str) -> String {
    hex::encode(Sha256::digest(npub.as_bytes()))
}

fn integrity_secret(state: &AppState) -> &str {
    &state.config.admin.key_integrity_secret
}

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub purpose: String,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct ProofRequest {
    /// `Nostr <base64(event)>` signed-action token.
    pub token: String,
    /// The server-issued single-use nonce the action binds.
    pub nonce: String,
}

#[derive(Debug, Serialize)]
pub struct ErasureRequestResponse {
    pub erasure_id: String,
    pub status: String,
    pub scheduled_for: String,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: String,
}

/// Verify a proof for `purpose` over `action_path`, consume the nonce, and
/// resolve the signer to a user (if any). The opaque `Err` is a single 401.
async fn prove(
    state: &Arc<AppState>,
    body: &ProofRequest,
    purpose: &str,
    action_path: &str,
    target: Option<(&str, &str)>,
) -> Result<(String, Option<User>), AppError> {
    let fail = || AppError::AuthError("Invalid erasure proof".into());
    let url = erasure_url(state, action_path)?;
    let descriptor_path = format!("/api/v1{action_path}");
    let payload = descriptor_sha256(&request_descriptor("POST", &descriptor_path, "", b""));
    let pubkey = verify_signed_action(
        &body.token,
        &url,
        "POST",
        purpose,
        &body.nonce,
        &payload,
        target,
        None,
        Utc::now().timestamp(),
        ACTION_MAX_AGE_SECS,
    )
    .map_err(|_| fail())?;
    // Single-use: consume AFTER the signature checks (a forged sig can't burn a
    // victim's nonce; a replay loses the race).
    if state
        .db
        .consume_challenge(&body.nonce, purpose)
        .await?
        .is_none()
    {
        return Err(fail());
    }
    let user = state.db.find_user_by_nostr_pubkey(&pubkey).await?;
    Ok((pubkey, user))
}

// ── handlers ─────────────────────────────────────────────────────────────────

/// Issue a single-use nonce for one of the erasure purposes.
#[instrument(skip(state, req))]
pub async fn challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AppError> {
    ensure_enabled(&state)?;
    if !matches!(
        req.purpose.as_str(),
        PURPOSE_REQUEST | PURPOSE_CONFIRM | PURPOSE_CANCEL | PURPOSE_EXPORT
    ) {
        return Err(AppError::ValidationError("unknown erasure purpose".into()));
    }
    let challenge = state
        .db
        .issue_challenge(&req.purpose, None, CHALLENGE_TTL_SECS)
        .await?;
    Ok(Json(ChallengeResponse {
        challenge,
        expires_in: CHALLENGE_TTL_SECS,
    }))
}

/// Phase 1: request erasure. The absent-user path returns the identical shape
/// (no row written) so it does not become an account-existence oracle.
#[instrument(skip(state, body))]
pub async fn request_erasure(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ProofRequest>,
) -> Result<Json<ErasureRequestResponse>, AppError> {
    ensure_enabled(&state)?;
    let grace = state.config.retention.grace_period_hours as i64;
    let (pubkey, user) = prove(&state, &body, PURPOSE_REQUEST, "/account/erasure", None).await?;

    match user {
        Some(u) => {
            let req = state
                .db
                .request_erasure(u.id, &subject_hash(&pubkey), grace)
                .await?;
            let _ = state
                .db
                .record_admin_audit(
                    &audit("account_erasure_requested", &req.id),
                    integrity_secret(&state),
                )
                .await;
            info!(erasure_id = %req.id, "erasure requested");
            Ok(Json(ErasureRequestResponse {
                erasure_id: req.id.to_string(),
                status: req.status,
                scheduled_for: req.scheduled_for.to_rfc3339(),
            }))
        }
        None => {
            // Constant-shape: a synthetic id, no row, no audit.
            Ok(Json(ErasureRequestResponse {
                erasure_id: Uuid::new_v4().to_string(),
                status: "pending".into(),
                scheduled_for: (Utc::now() + chrono::Duration::hours(grace)).to_rfc3339(),
            }))
        }
    }
}

/// Phase 2: confirm (a second fresh proof bound to this `erasure_id`). Revokes
/// all the user's live sessions and starts the grace clock.
#[instrument(skip(state, body))]
pub async fn confirm_erasure(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ProofRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    ensure_enabled(&state)?;
    let id_str = id.to_string();
    let path = format!("/account/erasure/{id_str}/confirm");
    let (_pubkey, user) = prove(
        &state,
        &body,
        PURPOSE_CONFIRM,
        &path,
        Some(("erasure_id", &id_str)),
    )
    .await?;
    let user = user.ok_or_else(|| AppError::NotFound("no such erasure request".into()))?;

    let grace = state.config.retention.grace_period_hours as i64;
    let req = state
        .db
        .confirm_erasure_request(id, user.id, grace)
        .await?
        .ok_or_else(|| AppError::NotFound("no pending erasure request".into()))?;
    // Revoke live sessions immediately on confirmation.
    let _ = state.db.revoke_all_user_sessions(user.id).await;
    let _ = state
        .db
        .record_admin_audit(
            &audit("account_erasure_confirmed", &req.id),
            integrity_secret(&state),
        )
        .await;
    info!(erasure_id = %req.id, "erasure confirmed");
    Ok(Json(StatusResponse { status: req.status }))
}

/// Cancel a live erasure during grace (a fresh `erasure_cancel` proof).
#[instrument(skip(state, body))]
pub async fn cancel_erasure(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ProofRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    ensure_enabled(&state)?;
    let id_str = id.to_string();
    let path = format!("/account/erasure/{id_str}");
    let (_pubkey, user) = prove(
        &state,
        &body,
        PURPOSE_CANCEL,
        &path,
        Some(("erasure_id", &id_str)),
    )
    .await?;
    let user = user.ok_or_else(|| AppError::NotFound("no such erasure request".into()))?;

    let req = state
        .db
        .cancel_erasure_request(id, user.id)
        .await?
        .ok_or_else(|| AppError::NotFound("no live erasure request".into()))?;
    let _ = state
        .db
        .record_admin_audit(
            &audit("account_erasure_cancelled", &req.id),
            integrity_secret(&state),
        )
        .await;
    Ok(Json(StatusResponse { status: req.status }))
}

#[derive(Debug, Serialize)]
pub struct ExportKey {
    pub asset: String,
    pub public_key: String,
    pub public_spend_key: Option<String>,
    pub key_type: String,
}

#[derive(Debug, Serialize)]
pub struct ExportResponse {
    pub user_id: String,
    pub username: Option<String>,
    pub nostr_pubkey: Option<String>,
    pub created_at: String,
    pub keys: Vec<ExportKey>,
    /// Deliberately omits the server's copy of any view key (the holder already
    /// has the seed; echoing it would create a new exfil path).
    pub note: &'static str,
}

/// See-before-delete export of what the backend holds about the account. Strong
/// proof; omits view keys. (A hard per-day rate cap is a documented follow-up;
/// the signed-action proof is the load-bearing control.)
#[instrument(skip(state, body))]
pub async fn export(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ProofRequest>,
) -> Result<Json<ExportResponse>, AppError> {
    ensure_enabled(&state)?;
    let (_pubkey, user) = prove(&state, &body, PURPOSE_EXPORT, "/account/export", None).await?;
    let user = user.ok_or_else(|| AppError::AuthError("Invalid erasure proof".into()))?;

    let keys = state
        .db
        .get_user_keys(user.id)
        .await?
        .into_iter()
        .map(|k| ExportKey {
            asset: k.asset.to_string(),
            public_key: k.public_key,
            public_spend_key: k.public_spend_key,
            key_type: k.key_type,
        })
        .collect();
    let _ = state
        .db
        .record_admin_audit(
            &NewAdminAudit {
                action: "account_exported".into(),
                actor_kind: "user".into(),
                actor_pubkey_prefix: None,
                target: Some(user.id.to_string()),
                details: None,
                ip_address: None,
            },
            integrity_secret(&state),
        )
        .await;
    Ok(Json(ExportResponse {
        user_id: user.id.to_string(),
        username: user.username,
        nostr_pubkey: user.nostr_pubkey,
        created_at: user.created_at.to_rfc3339(),
        keys,
        note: "the backend stores no spend key or seed; view keys are not echoed",
    }))
}

fn audit(action: &str, erasure_id: &Uuid) -> NewAdminAudit {
    NewAdminAudit {
        action: action.into(),
        actor_kind: "user".into(),
        actor_pubkey_prefix: None,
        target: Some(erasure_id.to_string()),
        details: None,
        ip_address: None,
    }
}

/// Run one execution sweep: delete confirmed-past-grace accounts. Called by the
/// background sweeper. Returns the number executed.
#[instrument(skip(state))]
pub async fn run_erasure_sweep(state: &Arc<AppState>, batch: i64) -> Result<u64, AppError> {
    let due = state.db.due_erasure_requests(batch).await?;
    let purge = state.config.retention.purge_login_events;
    let secret = integrity_secret(state);
    let mut done = 0;
    for req in due {
        let Some(user_id) = req.user_id else { continue };
        match state
            .db
            .execute_erasure(req.id, user_id, purge, secret)
            .await
        {
            Ok(()) => done += 1,
            Err(e) => warn!(erasure_id = %req.id, error = %e, "erasure execution failed"),
        }
    }
    Ok(done)
}

/// Erasure routes, RELATIVE to the `/api/v1` mount point. Public (proof-gated).
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/account/erasure/challenge", post(challenge))
        .route("/account/erasure", post(request_erasure))
        .route("/account/erasure/:id/confirm", post(confirm_erasure))
        .route("/account/erasure/:id", delete(cancel_erasure))
        .route("/account/export", post(export))
}
