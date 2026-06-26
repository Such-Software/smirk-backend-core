//! Admin authentication ("Sign in with Smirk") — loopback plane.
//!
//! Auth is a NIP-98 *signed action*: the admin proves control of a private key
//! over a server-issued single-use nonce (AUTHN), and is authorized by the MAC'd
//! allowlist (AUTHZ). The two are composed in [`admin_guard`] so a protected
//! handler physically cannot run without both. Every failure — bad signature,
//! good signature for a non-admin, missing session — collapses to the same
//! opaque `401`, so the surface is not an enumeration oracle. Tokens are minted
//! by [`crate::core::admin_session`] (distinct secret/audience); sessions and the
//! login audit row are written in one transaction (fail-closed).
//!
//! These routes are served only on the loopback admin plane (see
//! [`crate::admin_router`]); they are intentionally absent from the public
//! OpenAPI surface.

use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use subtle::ConstantTimeEq;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use crate::api::middleware::{bearer_token, client_ip};
use crate::core::admin_session::AdminSessionManager;
use crate::core::crypto::nip98::{descriptor_sha256, request_descriptor, verify_signed_action};
use crate::core::session::hash_refresh_token;
use crate::error::AppError;
use crate::models::db::{NewAdminAudit, NewAdminSession};
use crate::AppState;

/// Admin-login nonce lifetime.
const ADMIN_CHALLENGE_TTL_SECS: i64 = 120;
/// Freshness window for the signed action (tight — state-change grade).
const ADMIN_ACTION_MAX_AGE_SECS: i64 = 30;
/// How many hex chars of an actor pubkey land in the audit trail (no full key).
const PUBKEY_PREFIX_LEN: usize = 16;

// ── helpers ──────────────────────────────────────────────────────────────────

/// One opaque failure for every admin-auth rejection (no enumeration oracle).
fn admin_auth_fail() -> AppError {
    AppError::AuthError("Invalid admin credentials".into())
}

fn admin_manager(state: &AppState) -> Result<&AdminSessionManager, AppError> {
    state
        .admin_sessions
        .as_ref()
        .ok_or_else(|| AppError::NotFound("admin surface is not enabled".into()))
}

/// The absolute URL the signed action's `u` tag must bind (config, never Host).
fn admin_verify_url(state: &AppState) -> String {
    format!(
        "{}/admin/auth/verify",
        state.config.admin.public_url.trim_end_matches('/')
    )
}

/// A stable per-instance id bound into the signed action, so a challenge signed
/// for this instance cannot be relayed to another.
fn admin_instance_id(state: &AppState) -> String {
    hex::encode(Sha256::digest(state.config.admin.public_url.as_bytes()))[..16].to_string()
}

fn pubkey_prefix(pubkey: &str) -> String {
    pubkey.chars().take(PUBKEY_PREFIX_LEN).collect()
}

// ── guard ────────────────────────────────────────────────────────────────────

/// AUTHN (valid admin access token + live session) + AUTHZ (active, MAC-valid,
/// activated allowlist entry), composed. Injected into protected handlers.
#[derive(Debug, Clone)]
pub struct AdminContext {
    pub pubkey: String,
    pub admin_key_id: Uuid,
    pub session_id: Uuid,
}

/// Resolve and authorize the admin behind a request, or a single opaque 401.
pub async fn admin_guard(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<AdminContext, AppError> {
    let mgr = admin_manager(state).map_err(|_| admin_auth_fail())?;
    let token = bearer_token(headers).map_err(|_| admin_auth_fail())?;
    let info = mgr.verify_access(token).map_err(|_| admin_auth_fail())?;

    // Live session for this access token's jti (rejects revoked/expired).
    let session = state
        .db
        .find_active_admin_session_by_jti(&info.jti)
        .await?
        .ok_or_else(admin_auth_fail)?;

    // Live, uncached allowlist re-check (MAC re-verified inside): must be active
    // AND activated (a pending key is not yet authorized for protected routes).
    let secret = &state.config.admin.key_integrity_secret;
    let key = state
        .db
        .get_active_admin_key(&info.pubkey, secret)
        .await?
        .filter(|k| k.activated_at.is_some())
        .ok_or_else(admin_auth_fail)?;

    Ok(AdminContext {
        pubkey: info.pubkey,
        admin_key_id: key.id,
        session_id: session.id,
    })
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AdminChallengeResponse {
    /// The single-use nonce to bind in the signed action's `challenge` tag.
    pub challenge: String,
    /// The URL the signed action's `u` tag must equal.
    pub url: String,
    /// The instance id to bind in the `instance_id` tag.
    pub instance_id: String,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct AdminVerifyRequest {
    /// `Nostr <base64(event)>` signed-action token.
    pub admin_token: String,
    /// The nonce from the challenge (must equal the event's `challenge` tag).
    pub challenge: String,
}

#[derive(Debug, Serialize)]
pub struct AdminTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct AdminRefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AdminMeResponse {
    pub pubkey: String,
    pub admin_key_id: String,
}

#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

// ── handlers ─────────────────────────────────────────────────────────────────

/// Issue a single-use admin-login nonce + the binding descriptor the wallet signs.
#[instrument(skip(state))]
pub async fn admin_challenge(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AdminChallengeResponse>, AppError> {
    admin_manager(&state)?;
    let challenge = state
        .db
        .issue_challenge("admin_login", None, ADMIN_CHALLENGE_TTL_SECS)
        .await?;
    Ok(Json(AdminChallengeResponse {
        challenge,
        url: admin_verify_url(&state),
        instance_id: admin_instance_id(&state),
        expires_in: ADMIN_CHALLENGE_TTL_SECS,
    }))
}

/// Verify the signed action, consume the nonce, authorize, and mint a session.
#[instrument(skip(state, headers, peer, req))]
pub async fn admin_verify(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<AdminVerifyRequest>,
) -> Result<Json<AdminTokenResponse>, AppError> {
    let mgr = admin_manager(&state)?;
    let ip = client_ip(&state, &headers, peer);
    let secret = &state.config.admin.key_integrity_secret;

    // 1. Prove the signature + bindings (purpose/nonce/descriptor/instance). The
    // descriptor binds the verify URL with an EMPTY body (the proof rides in the
    // JSON body and cannot also be inside the thing it signs).
    let url = admin_verify_url(&state);
    let descriptor = request_descriptor("POST", "/admin/auth/verify", "", b"");
    let payload = descriptor_sha256(&descriptor);
    let instance_id = admin_instance_id(&state);
    let pubkey = verify_signed_action(
        &req.admin_token,
        &url,
        "POST",
        "admin_login",
        &req.challenge,
        &payload,
        None,
        Some(&instance_id),
        Utc::now().timestamp(),
        ADMIN_ACTION_MAX_AGE_SECS,
    )
    .map_err(|_| admin_auth_fail())?;

    // 2. Single-use: consume AFTER the signature checks, so a forged signature
    // cannot burn a victim's nonce. A replay/expired nonce loses the race.
    if state
        .db
        .consume_challenge(&req.challenge, "admin_login")
        .await?
        .is_none()
    {
        return Err(admin_auth_fail());
    }

    // 3. AUTHZ: a non-revoked, MAC-valid allowlist entry (pending allowed for the
    // first login, which activates it).
    let key = state
        .db
        .get_active_admin_key(&pubkey, secret)
        .await?
        .ok_or_else(admin_auth_fail)?;
    if key.activated_at.is_none() {
        if let Some(deadline) = key.activation_deadline {
            if Utc::now() > deadline {
                warn!(admin_key_id = %key.id, "pending admin key past activation deadline");
                return Err(admin_auth_fail());
            }
        }
        state.db.activate_admin_key(key.id, secret).await?;
    }

    // 4. Mint + persist session + audit (audit shares the session's transaction).
    let session_id = Uuid::new_v4();
    let pair = mgr.create_token_pair(&pubkey, session_id)?;
    let refresh_hash = hash_refresh_token(
        &pair.refresh_token,
        &state.config.secrets.refresh_token_pepper,
    );
    let audit = NewAdminAudit {
        action: "admin_login".into(),
        actor_kind: "admin".into(),
        actor_pubkey_prefix: Some(pubkey_prefix(&pubkey)),
        target: None,
        details: None,
        ip_address: Some(IpNetwork::from(ip)),
    };
    state
        .db
        .create_admin_session_audited(
            NewAdminSession {
                id: session_id,
                admin_key_id: key.id,
                pubkey: pubkey.clone(),
                refresh_token_hash: refresh_hash,
                access_jti: pair.access_jti.clone(),
                device_info: None,
                ip_address: Some(IpNetwork::from(ip)),
                expires_at: Utc::now() + mgr.refresh_ttl(),
            },
            &audit,
            secret,
        )
        .await?;
    state.db.touch_admin_key_last_used(key.id).await?;

    info!(admin_key_id = %key.id, "admin authenticated");
    Ok(Json(AdminTokenResponse {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        expires_in: pair.expires_in,
    }))
}

/// Re-run the FULL authorization, then mint a fresh access token (rotating the
/// session jti). A revoked admin's in-flight refresh token cannot mint anew.
#[instrument(skip(state, req))]
pub async fn admin_refresh(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AdminRefreshRequest>,
) -> Result<Json<AdminTokenResponse>, AppError> {
    let mgr = admin_manager(&state)?;
    let (pubkey, session_id) = mgr
        .verify_refresh(&req.refresh_token)
        .map_err(|_| admin_auth_fail())?;

    // Re-authorize against the live allowlist (closes the "8h refresh is the real
    // blast radius" gap).
    let secret = &state.config.admin.key_integrity_secret;
    let key = state
        .db
        .get_active_admin_key(&pubkey, secret)
        .await?
        .filter(|k| k.activated_at.is_some())
        .ok_or_else(admin_auth_fail)?;

    // The session must still be live, and the presented refresh token must match
    // the one bound to it (constant-time).
    let session = state
        .db
        .find_active_admin_session_by_id(session_id)
        .await?
        .ok_or_else(admin_auth_fail)?;
    let presented = hash_refresh_token(
        &req.refresh_token,
        &state.config.secrets.refresh_token_pepper,
    );
    let hash_ok: bool = presented
        .as_bytes()
        .ct_eq(session.refresh_token_hash.as_bytes())
        .into();
    if !hash_ok || session.admin_key_id != key.id {
        return Err(admin_auth_fail());
    }

    let (access_token, jti, expires_in) = mgr.mint_access_token(&pubkey)?;
    state
        .db
        .rotate_admin_session_jti(session_id, &jti)
        .await?
        .ok_or_else(admin_auth_fail)?;

    Ok(Json(AdminTokenResponse {
        access_token,
        refresh_token: req.refresh_token,
        expires_in,
    }))
}

/// Revoke the current admin session.
#[instrument(skip(state, headers))]
pub async fn admin_logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<OkResponse>, AppError> {
    let ctx = admin_guard(&state, &headers).await?;
    state.db.revoke_admin_session(ctx.session_id).await?;
    let secret = &state.config.admin.key_integrity_secret;
    let _ = state
        .db
        .record_admin_audit(
            &NewAdminAudit {
                action: "admin_logout".into(),
                actor_kind: "admin".into(),
                actor_pubkey_prefix: Some(pubkey_prefix(&ctx.pubkey)),
                target: None,
                details: None,
                ip_address: None,
            },
            secret,
        )
        .await;
    Ok(Json(OkResponse { ok: true }))
}

/// Whoami for the authenticated admin (also exercises the guard).
#[instrument(skip(state, headers))]
pub async fn admin_me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AdminMeResponse>, AppError> {
    let ctx = admin_guard(&state, &headers).await?;
    Ok(Json(AdminMeResponse {
        pubkey: ctx.pubkey,
        admin_key_id: ctx.admin_key_id.to_string(),
    }))
}

// ── router ───────────────────────────────────────────────────────────────────

/// Admin-plane routes. Mounted by [`crate::admin_router`] on the loopback socket.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/auth/challenge", post(admin_challenge))
        .route("/admin/auth/verify", post(admin_verify))
        .route("/admin/auth/refresh", post(admin_refresh))
        .route("/admin/auth/logout", post(admin_logout))
        .route("/admin/me", get(admin_me))
}
