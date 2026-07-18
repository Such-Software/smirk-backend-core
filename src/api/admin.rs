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
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
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
use crate::infra::db::{AddKeyOutcome, RevokeKeyOutcome};
use crate::models::db::{AdminKey, NewAdminAudit, NewAdminKey, NewAdminSession};
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
        state.cfg().admin.public_url.trim_end_matches('/')
    )
}

/// A stable per-instance id bound into the signed action, so a challenge signed
/// for this instance cannot be relayed to another.
fn admin_instance_id(state: &AppState) -> String {
    hex::encode(Sha256::digest(state.cfg().admin.public_url.as_bytes()))[..16].to_string()
}

fn pubkey_prefix(pubkey: &str) -> String {
    pubkey.chars().take(PUBKEY_PREFIX_LEN).collect()
}

/// Whether a request `Host` is allowed on the admin plane. A missing Host is
/// permitted (a DNS-rebinding attack must supply the attacker's Host, and the
/// loopback bind is the primary control); a PRESENT host must be loopback or the
/// configured onion. Defeats DNS-rebinding against the loopback socket.
fn host_allowed(host: &str, onion: Option<&str>) -> bool {
    if host.is_empty() {
        return true;
    }
    let h = host.to_ascii_lowercase();
    // IPv6 loopback, anchored: exactly "[::1]" or "[::1]:port" (not "[::1].evil").
    if h == "[::1]" || h.starts_with("[::1]:") || h == "::1" {
        return true;
    }
    let bare = h.split(':').next().unwrap_or(&h);
    if matches!(bare, "localhost" | "127.0.0.1") {
        return true;
    }
    if let Some(o) = onion {
        let o = o.to_ascii_lowercase();
        if !o.is_empty() && (bare == o || h == o) {
            return true;
        }
    }
    false
}

/// Admin-plane middleware: Host allowlist (anti DNS-rebinding) + anti-clickjacking
/// response headers. The loopback bind is the primary control; these are
/// defense-in-depth for the Tor/tunnel paths and any browser-reachable case.
pub async fn admin_plane_guard(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    // Compute the response on both paths, then apply the security headers once so
    // the 403 Host-reject carries them too.
    let mut resp = if host_allowed(host, state.cfg().admin.onion.as_deref()) {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "forbidden").into_response()
    };
    let h = resp.headers_mut();
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "content-security-policy",
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    resp
}

/// Validate an x-only secp256k1 pubkey: exactly 64 lowercase hex chars.
fn validate_admin_pubkey(pubkey: &str) -> Result<(), AppError> {
    let ok = pubkey.len() == 64
        && pubkey
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(AppError::ValidationError(
            "pubkey must be 64 lowercase hex chars".into(),
        ))
    }
}

/// Lifecycle label for an allowlist row.
fn key_status(k: &AdminKey) -> &'static str {
    if k.revoked_at.is_some() {
        "revoked"
    } else if k.activated_at.is_none() {
        "pending"
    } else {
        "active"
    }
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
    let secret = &state.cfg().admin.key_integrity_secret;
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
    let secret = &state.cfg().admin.key_integrity_secret;

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
        &state.cfg().secrets.refresh_token_pepper,
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
    let secret = &state.cfg().admin.key_integrity_secret;
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
        &state.cfg().secrets.refresh_token_pepper,
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
    let secret = &state.cfg().admin.key_integrity_secret;
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

// ── keys CRUD ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AddKeyRequest {
    pub pubkey: String,
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KeyResponse {
    pub id: String,
    pub pubkey: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct AdminKeyView {
    pub id: String,
    pub pubkey: String,
    pub label: Option<String>,
    pub scope: String,
    pub status: String,
    pub created_at: String,
    pub activated_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KeysListResponse {
    pub keys: Vec<AdminKeyView>,
}

fn key_view(k: &AdminKey) -> AdminKeyView {
    AdminKeyView {
        id: k.id.to_string(),
        pubkey: k.pubkey.clone(),
        label: k.label.clone(),
        scope: k.scope.clone(),
        status: key_status(k).to_string(),
        created_at: k.created_at.to_rfc3339(),
        activated_at: k.activated_at.map(|t| t.to_rfc3339()),
        revoked_at: k.revoked_at.map(|t| t.to_rfc3339()),
    }
}

/// Build a pending `NewAdminKey` from a validated request, created over the
/// network (so `created_by_kind = admin`), with the configured activation TTL.
fn pending_key(state: &AppState, pubkey: String, label: Option<String>) -> NewAdminKey {
    NewAdminKey {
        pubkey,
        label,
        scope: "admin".into(),
        created_by_kind: "admin".into(),
        activation_deadline: Some(
            Utc::now() + Duration::days(state.cfg().admin.pending_key_ttl_days as i64),
        ),
    }
}

/// Add a pending allowlist entry (it activates on its holder's first login).
#[instrument(skip(state, headers, req))]
pub async fn admin_keys_add(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AddKeyRequest>,
) -> Result<Json<KeyResponse>, AppError> {
    let ctx = admin_guard(&state, &headers).await?;
    let pubkey = req.pubkey.to_lowercase();
    validate_admin_pubkey(&pubkey)?;

    let secret = &state.cfg().admin.key_integrity_secret;
    let audit = NewAdminAudit {
        action: "admin_key_added".into(),
        actor_kind: "admin".into(),
        actor_pubkey_prefix: Some(pubkey_prefix(&ctx.pubkey)),
        target: Some(pubkey_prefix(&pubkey)),
        details: None,
        ip_address: None,
    };
    // The live-key cap is enforced INSIDE the insert transaction (race-free).
    let key = match state
        .db
        .create_admin_key_audited(
            pending_key(&state, pubkey, req.label),
            &audit,
            secret,
            state.cfg().admin.max_keys as i64,
        )
        .await?
    {
        AddKeyOutcome::Created(key) => key,
        AddKeyOutcome::CapReached => {
            return Err(AppError::Forbidden(
                "admin key limit reached; revoke an existing key first".into(),
            ))
        }
    };
    let status = key_status(&key).to_string();
    Ok(Json(KeyResponse {
        id: key.id.to_string(),
        pubkey: key.pubkey,
        status,
    }))
}

/// List all allowlist entries (active, pending, revoked).
#[instrument(skip(state, headers))]
pub async fn admin_keys_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<KeysListResponse>, AppError> {
    admin_guard(&state, &headers).await?;
    let keys = state.db.list_admin_keys().await?;
    Ok(Json(KeysListResponse {
        keys: keys.iter().map(key_view).collect(),
    }))
}

/// Soft-revoke a key (+ its sessions). Refuses to revoke the LAST live key over
/// the network — that is CLI-only, so an operator cannot lock everyone out.
#[instrument(skip(state, headers))]
pub async fn admin_keys_revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<OkResponse>, AppError> {
    let ctx = admin_guard(&state, &headers).await?;
    let secret = &state.cfg().admin.key_integrity_secret;
    let audit = NewAdminAudit {
        action: "admin_key_revoked".into(),
        actor_kind: "admin".into(),
        actor_pubkey_prefix: Some(pubkey_prefix(&ctx.pubkey)),
        target: Some(id.to_string()),
        details: None,
        ip_address: None,
    };
    // The last-key floor is enforced INSIDE the revoke transaction (race-free):
    // concurrent revokes cannot both pass the check and empty the allowlist.
    match state
        .db
        .revoke_admin_key_full(id, &audit, secret, true)
        .await?
    {
        RevokeKeyOutcome::Revoked(_) => Ok(Json(OkResponse { ok: true })),
        RevokeKeyOutcome::NotFound => Err(AppError::NotFound(
            "admin key not found or already revoked".into(),
        )),
        RevokeKeyOutcome::WouldEmptyAllowlist => Err(AppError::Forbidden(
            "refusing to revoke the last admin key over the network; use the CLI".into(),
        )),
    }
}

/// Atomically rotate a key: revoke the old one (+ its sessions) and add a fresh
/// pending one. Permitted on the last live key (it is add+revoke, not a bare
/// revoke), so it is the in-band recovery for a compromised solo key.
#[instrument(skip(state, headers, req))]
pub async fn admin_keys_rotate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<AddKeyRequest>,
) -> Result<Json<KeyResponse>, AppError> {
    let ctx = admin_guard(&state, &headers).await?;
    let pubkey = req.pubkey.to_lowercase();
    validate_admin_pubkey(&pubkey)?;
    let secret = &state.cfg().admin.key_integrity_secret;
    let audit = NewAdminAudit {
        action: "admin_key_rotated".into(),
        actor_kind: "admin".into(),
        actor_pubkey_prefix: Some(pubkey_prefix(&ctx.pubkey)),
        target: Some(id.to_string()),
        details: None,
        ip_address: None,
    };
    let key = state
        .db
        .rotate_admin_key(id, pending_key(&state, pubkey, req.label), &audit, secret)
        .await?
        .ok_or_else(|| AppError::NotFound("admin key not found or already revoked".into()))?;
    let status = key_status(&key).to_string();
    Ok(Json(KeyResponse {
        id: key.id.to_string(),
        pubkey: key.pubkey,
        status,
    }))
}

// ── features (read-only view) ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct Downgrade {
    pub feature: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct AdminFeaturesResponse {
    pub effective: crate::api::capabilities::CapabilitiesResponse,
    /// Flags that are ON in config but serve as disabled (missing secret/URL).
    /// Exposed only to the admin — the public capabilities hides the reason.
    pub downgrades: Vec<Downgrade>,
}

/// Admin-only view of the resolved feature state + why anything is downgraded.
/// (Runtime mutation — PUT /admin/features + DB override — is deferred; flags are
/// env/config-driven for now.)
#[instrument(skip(state, headers))]
pub async fn admin_features(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AdminFeaturesResponse>, AppError> {
    admin_guard(&state, &headers).await?;
    let cfg = &state.cfg();
    let effective = crate::api::capabilities::effective_capabilities(cfg);

    let mut downgrades = Vec::new();
    let mut note = |on: bool, eff: bool, feature: &str, reason: &str| {
        if on && !eff {
            downgrades.push(Downgrade {
                feature: feature.into(),
                reason: reason.into(),
            });
        }
    };
    let c = &cfg.features.chains;
    note(
        c.btc,
        effective.chains.btc.enabled,
        "btc",
        "BTC_ELECTRUM_URL/fallbacks unset",
    );
    note(
        c.ltc,
        effective.chains.ltc.enabled,
        "ltc",
        "LTC_ELECTRUM_URL/fallbacks unset",
    );
    note(
        c.xmr,
        effective.chains.xmr.enabled,
        "xmr",
        "XMR_LWS_ADMIN_KEY unset",
    );
    note(
        c.wow,
        effective.chains.wow.enabled,
        "wow",
        "WOW_LWS_ADMIN_KEY unset",
    );
    note(
        c.grin,
        effective.chains.grin.enabled,
        "grin",
        "GRIN_OWNER_API_SECRET unset",
    );
    note(
        cfg.features.nostr_identity,
        effective.features.nostr_identity,
        "nostr_identity",
        "PUBLIC_API_URL unset",
    );

    Ok(Json(AdminFeaturesResponse {
        effective,
        downgrades,
    }))
}

// ── router ───────────────────────────────────────────────────────────────────

/// Admin-plane routes. Mounted by [`crate::admin_router`] on the loopback socket.
// ── Operator config (GET + PUT /admin/config) ─────────────────────────────────
// The editable settings surface, on the effective-config layer (config_overlay.rs).
// GET reports each field's effective value + the DB overlay + per-section version +
// runtime_class + restart_pending. PUT validates a patch with the SAME rules boot
// uses, persists the changed sections (audited, version-guarded), then hot-swaps the
// effective config for runtime-safe edits or flags restart-required.

#[derive(serde::Serialize)]
struct AdminConfigResponse {
    /// Effective value of every editable field (all populated).
    effective: crate::config_overlay::SettingsOverlay,
    /// DB overlay (operator-set values only): a field present here has source=db;
    /// absent = env/default.
    overlay: crate::config_overlay::SettingsOverlay,
    /// Persisted version per section (echo back as `expected_versions` on PUT).
    versions: std::collections::HashMap<String, i64>,
    /// "section.field" -> runtime-safe | restart-required.
    runtime_class: std::collections::HashMap<String, crate::config_overlay::RuntimeClass>,
    /// A persisted change hasn't been applied to the running config yet (needs restart).
    restart_pending: bool,
}

#[instrument(skip(state, headers))]
pub async fn admin_config_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AdminConfigResponse>, AppError> {
    admin_guard(&state, &headers).await?;
    let secret = state.cfg().admin.key_integrity_secret.clone();

    let overlay = state.db.load_settings_overlay(&secret).await?;
    let versions = state.db.settings_versions().await?;
    let effective = state.cfg().editable_overlay();

    // restart_pending: the persisted overlay's effective view differs from the RUNNING
    // effective view (a restart-required field was saved but not yet applied).
    let restart_pending = match state.config_base.apply_overlay(&overlay) {
        Ok(persisted) => {
            serde_json::to_value(persisted.editable_overlay()).ok()
                != serde_json::to_value(&effective).ok()
        }
        Err(_) => false,
    };

    let runtime_class = crate::config_overlay::EDITABLE_FIELDS
        .iter()
        .map(|(section, field)| {
            (
                format!("{section}.{field}"),
                crate::config_overlay::runtime_class(section, field),
            )
        })
        .collect();

    Ok(Json(AdminConfigResponse {
        effective,
        overlay,
        versions,
        runtime_class,
        restart_pending,
    }))
}

#[derive(serde::Deserialize)]
pub struct PutConfigRequest {
    /// Sparse patch: only the fields to change (unset fields left as-is).
    patch: crate::config_overlay::SettingsOverlay,
    /// Optional optimistic-concurrency guard: expected current version per touched
    /// section. A mismatch is a 409 (another operator edited it first).
    #[serde(default)]
    expected_versions: std::collections::HashMap<String, i64>,
}

#[derive(serde::Serialize)]
struct PutConfigResponse {
    /// "runtime" = hot-swapped, live now. "restart-required" = persisted, applies on
    /// the next (graceful) restart.
    applied: String,
    restart_pending: bool,
}

#[instrument(skip(state, headers, req))]
pub async fn admin_config_put(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PutConfigRequest>,
) -> Result<Json<PutConfigResponse>, AppError> {
    let ctx = admin_guard(&state, &headers).await?;
    let secret = state.cfg().admin.key_integrity_secret.clone();

    let patch_json = serde_json::to_value(&req.patch)
        .map_err(|e| AppError::ValidationError(format!("bad patch: {e}")))?;
    let patch_obj = patch_json.as_object().cloned().unwrap_or_default();

    // merged = persisted overlay + patch (patch's non-null fields win), then validate
    // with the SAME rules boot uses. Reject the whole PUT if invalid (nothing persists).
    let persisted = state.db.load_settings_overlay(&secret).await?;
    let mut merged_json =
        serde_json::to_value(&persisted).map_err(|e| AppError::Internal(e.to_string()))?;
    json_merge_skip_null(&mut merged_json, &patch_json);
    let merged: crate::config_overlay::SettingsOverlay = serde_json::from_value(merged_json.clone())
        .map_err(|e| AppError::ValidationError(format!("bad settings: {e}")))?;
    let candidate = state.config_base.apply_overlay(&merged)?; // ValidationError -> 400

    // Classify the CHANGED fields: which sections changed + does any need a restart?
    let mut any_restart = false;
    let mut changed_sections: Vec<String> = Vec::new();
    for (section, fields) in &patch_obj {
        let Some(fields) = fields.as_object() else { continue };
        let touched: Vec<&String> = fields
            .iter()
            .filter(|(_, v)| !v.is_null())
            .map(|(k, _)| k)
            .collect();
        if touched.is_empty() {
            continue;
        }
        changed_sections.push(section.clone());
        for field in touched {
            if crate::config_overlay::runtime_class(section, field)
                == crate::config_overlay::RuntimeClass::RestartRequired
            {
                any_restart = true;
            }
        }
    }
    if changed_sections.is_empty() {
        return Err(AppError::ValidationError("empty config patch".into()));
    }

    // Persist each changed section's merged doc, audited + version-guarded.
    let merged_obj = merged_json.as_object().cloned().unwrap_or_default();
    for section in &changed_sections {
        let doc = merged_obj
            .get(section)
            .cloned()
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let audit = NewAdminAudit {
            action: "config_updated".into(),
            actor_kind: "admin".into(),
            actor_pubkey_prefix: Some(pubkey_prefix(&ctx.pubkey)),
            target: Some(section.clone()),
            details: Some(serde_json::json!({ "section": section })),
            ip_address: None,
        };
        state
            .db
            .put_setting_audited(
                section,
                &doc,
                Some(ctx.admin_key_id),
                req.expected_versions.get(section).copied(),
                &audit,
                &secret,
            )
            .await?;
    }

    // Apply. Runtime-safe-only edits hot-swap the effective config atomically (live on
    // the next request); any restart-required field is persisted + flagged so the
    // operator applies it with a graceful restart.
    if any_restart {
        // In `auto` mode, self-restart shortly AFTER responding so the persisted change
        // takes effect (systemd `Restart=always` brings us back). The console warns the
        // operator before saving in auto mode; `manual` just flags restart_pending.
        if state.cfg().console.restart_apply_mode == crate::config::RestartApplyMode::Auto {
            let shutdown = state.shutdown.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(750)).await;
                tracing::info!("config auto-apply: self-restart to apply a restart-required change");
                shutdown.notify_one();
            });
        }
        Ok(Json(PutConfigResponse {
            applied: "restart-required".into(),
            restart_pending: true,
        }))
    } else {
        state.config.store(std::sync::Arc::new(candidate));
        Ok(Json(PutConfigResponse {
            applied: "runtime".into(),
            restart_pending: false,
        }))
    }
}

/// Recursively merge `patch` into `base` (JSON objects); a `null` in `patch` means
/// "leave unset" and is skipped, so a sparse overlay patch only sets present fields.
fn json_merge_skip_null(base: &mut serde_json::Value, patch: &serde_json::Value) {
    match (base, patch) {
        (serde_json::Value::Object(b), serde_json::Value::Object(p)) => {
            for (k, pv) in p {
                if pv.is_null() {
                    continue;
                }
                json_merge_skip_null(
                    b.entry(k.clone()).or_insert(serde_json::Value::Null),
                    pv,
                );
            }
        }
        (b, p) => *b = p.clone(),
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/auth/challenge", post(admin_challenge))
        .route("/admin/auth/verify", post(admin_verify))
        .route("/admin/auth/refresh", post(admin_refresh))
        .route("/admin/auth/logout", post(admin_logout))
        .route("/admin/me", get(admin_me))
        .route("/admin/features", get(admin_features))
        .route("/admin/keys", post(admin_keys_add).get(admin_keys_list))
        .route("/admin/keys/:id", delete(admin_keys_revoke))
        .route("/admin/keys/:id/rotate", post(admin_keys_rotate))
        .route("/admin/config", get(admin_config_get).put(admin_config_put))
}

#[cfg(test)]
mod tests {
    use super::host_allowed;

    #[test]
    fn host_allowlist() {
        // Missing host is allowed (rebinding must supply a host; bind is primary).
        assert!(host_allowed("", None));
        // Loopback forms.
        assert!(host_allowed("localhost", None));
        assert!(host_allowed("localhost:8081", None));
        assert!(host_allowed("127.0.0.1", None));
        assert!(host_allowed("127.0.0.1:8081", None));
        assert!(host_allowed("[::1]:8081", None));
        // A foreign host (DNS-rebinding) is rejected.
        assert!(!host_allowed("evil.example", None));
        assert!(!host_allowed("attacker.test:8081", None));
        // Anchored: a host merely STARTING with a loopback form is rejected.
        assert!(!host_allowed("[::1].evil.com", None));
        assert!(!host_allowed("localhost.evil.com", None));
        assert!(!host_allowed("127.0.0.1.evil.com", None));
        // The configured onion is allowed; others still rejected.
        assert!(host_allowed("abc.onion", Some("abc.onion")));
        assert!(host_allowed("abc.onion:80", Some("abc.onion")));
        assert!(!host_allowed("evil.onion", Some("abc.onion")));
    }
}
