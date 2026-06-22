//! Authentication handlers (core).
//!
//! Identity is the wallet's own key material — never a third-party platform
//! login. Three entry points mint a session, all converging on the same
//! `(access, refresh)` JWT pair backed by a revocable DB session row:
//!
//! * [`extension_register`] — proves control of the wallet's BTC key (a signed
//!   timestamp), optionally gated by proof-of-work, and get-or-creates the user
//!   keyed by `pubkey_hash`. A derivation-scheme rotation (a known
//!   `seed_fingerprint` at a new `pubkey_hash`) re-points an EXISTING user row
//!   ONLY when the request additionally proves control of the BTC key already on
//!   file for that user — never on a bare (unauthenticated) fingerprint.
//! * [`nostr_login`] — NIP-98 (login grade) over the `Authorization` header.
//!   Resolves an already-linked npub to its user; it NEVER creates a user.
//! * [`refresh_token`] — rotates a valid, still-active refresh token.
//!
//! Plus [`check_restore`] (rate-limited per fingerprint AND per IP,
//! enumeration-safe), [`pow_challenge`], [`logout`], [`get_me`], and
//! [`nostr_link`] (a state-change requiring both a JWT and a signed-action
//! proof).
//!
//! Conventions enforced here:
//! * The shared [`crate::core::session::SessionManager`] is read from
//!   `state.sessions`; refresh tokens are stored peppered with
//!   `config.secrets.refresh_token_pepper`.
//! * NIP-98 binds the canonical `config.identity.public_api_url`, never the
//!   request `Host`. If that is unset, the Nostr endpoints fail closed.
//! * Foreign error detail (sqlx, k256, jsonwebtoken) is routed to tracing; the
//!   client gets a generic literal — `AppError` SAFE variants are literals.
//! * All request/response fields are snake_case (the wallet client expects it).
//!
//! Routes are registered RELATIVE to `/api/v1` (e.g. `/auth/extension`); see
//! [`routes`]. The app is expected to nest this router under `/api/v1` and serve
//! it with `into_make_service_with_connect_info::<SocketAddr>()` so the
//! [`client_ip`] extractor has the real TCP peer.

use std::net::SocketAddr;
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
use tracing::{info, instrument, warn};
use uuid::Uuid;

use crate::api::middleware::{client_ip, extract_user_id_from_token};
use crate::core::crypto::nip98::{
    descriptor_sha256, request_descriptor, verify_nip98, verify_signed_action,
};
use crate::core::crypto::signatures::verify_bitcoin_signature;
use crate::core::session::{hash_refresh_token, Platform};
use crate::error::AppError;
use crate::models::db::{AssetType, NewSession, NewUserKey};
use crate::AppState;

// ── shared constants ────────────────────────────────────────────────────────

/// Replay window for a NIP-98 LOGIN token (seconds). Wide enough for client
/// clock skew, tight enough to bound replay.
const NIP98_LOGIN_MAX_AGE_SECS: i64 = 60;

/// Replay window for a NIP-98 STATE-CHANGE (signed action) token (seconds).
/// Deliberately tighter than login.
const NIP98_ACTION_MAX_AGE_SECS: i64 = 30;

/// Max accepted drift for the extension's signed-timestamp proof (seconds).
const SIGNED_TS_MAX_DRIFT_SECS: i64 = 300;

/// Failed restore attempts (per fingerprint, last hour) that trip the gate.
const RESTORE_FAIL_THRESHOLD: i64 = 3;

/// All restore attempts (per IP, last hour) that trip the per-IP governor. This
/// bounds distinct-fingerprint scanning — the per-fingerprint counter alone
/// never trips when each candidate fingerprint is probed only once.
const RESTORE_IP_THRESHOLD: i64 = 30;

// ── shared DTOs ─────────────────────────────────────────────────────────────

/// Successful session response: a JWT pair plus minimal user info.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    /// Access-token lifetime in seconds.
    pub expires_in: i64,
    pub user: UserInfo,
    /// `true` when this request created the user (extension registration only).
    pub is_new: bool,
}

/// Minimal, non-enumerable user info returned to a signed-in client.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserInfo {
    pub id: String,
    pub username: Option<String>,
    /// Linked Nostr pubkey (x-only hex), if any.
    pub nostr_pubkey: Option<String>,
}

/// A per-asset public key submitted by the wallet.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct AssetPublicKey {
    pub asset: String,
    pub public_key: String,
    /// XMR/WOW only: public spend key.
    pub public_spend_key: Option<String>,
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Parse an asset string into [`AssetType`], or a 400.
fn parse_asset(asset: &str) -> Result<AssetType, AppError> {
    match asset.to_lowercase().as_str() {
        "btc" => Ok(AssetType::Btc),
        "ltc" => Ok(AssetType::Ltc),
        "xmr" => Ok(AssetType::Xmr),
        "wow" => Ok(AssetType::Wow),
        "grin" => Ok(AssetType::Grin),
        other => Err(AppError::ValidationError(format!("Invalid asset: {other}"))),
    }
}

/// Validate a reserved username (3-32 chars, `[a-z0-9_]`, no leading/trailing `_`).
fn validate_username(username: &str) -> Result<(), AppError> {
    if username.len() < 3 || username.len() > 32 {
        return Err(AppError::ValidationError(
            "Username must be 3-32 characters".into(),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(AppError::ValidationError(
            "Username must contain only lowercase letters, numbers, and underscores".into(),
        ));
    }
    if username.starts_with('_') || username.ends_with('_') {
        return Err(AppError::ValidationError(
            "Username cannot start or end with underscore".into(),
        ));
    }
    Ok(())
}

/// Whether the PoW gate applies to this registration. Consistent with the
/// feature flag: a disabled feature (`config.pow.enabled == false`) NEVER gates,
/// regardless of `required` / `required_for_pubkeys`. This is the handler-side
/// guard against the `POW_REQUIRED=true, FEATURE_POW=false` misconfiguration in
/// which `verify_payload` would otherwise run against an empty HMAC key (config
/// validation only requires `ALTCHA_HMAC_KEY` when the feature is enabled). When
/// disabled we never call `verify_payload`, so the empty key is never used.
fn pow_applies(state: &AppState, pubkey_hash_lc: &str) -> bool {
    state.config.pow.enabled && crate::core::pow::required_for(&state.config.pow, pubkey_hash_lc)
}

/// The canonical absolute URL a NIP-98 token must bind for `path` (the value of
/// the event's `u` tag). Built from `config.identity.public_api_url`, never the
/// request Host. Fail closed when unset (Nostr identity is disabled).
fn nip98_url(state: &AppState, path: &str) -> Result<String, AppError> {
    let base = state
        .config
        .identity
        .public_api_url
        .as_deref()
        .ok_or_else(|| {
            warn!("Nostr endpoint reached but PUBLIC_API_URL is unset; refusing");
            AppError::AuthError("Nostr authentication is not enabled".into())
        })?;
    Ok(format!("{}{}", base.trim_end_matches('/'), path))
}

/// Build [`UserInfo`] from a DB user.
fn user_info(user: &crate::models::db::User) -> UserInfo {
    UserInfo {
        id: user.id.to_string(),
        username: user.username.clone(),
        nostr_pubkey: user.nostr_pubkey.clone(),
    }
}

/// Mint a token pair, persist a session row (peppered refresh hash), and return
/// the pair. Centralizes the refresh-token peppering + session-row shape so it
/// cannot drift between the three login paths and the refresh rotation.
async fn issue_session(
    state: &AppState,
    user_id: Uuid,
    platform: Platform,
    device_info: &str,
    ip: Option<IpNetwork>,
) -> Result<crate::core::session::TokenPair, AppError> {
    let session_id = Uuid::new_v4();
    let pair = state
        .sessions
        .create_token_pair(user_id, platform, session_id)?;

    let refresh_token_hash = hash_refresh_token(
        &pair.refresh_token,
        &state.config.secrets.refresh_token_pepper,
    );
    let expires_at = Utc::now() + state.sessions.refresh_token_expiry();

    state
        .db
        .create_session(NewSession {
            user_id,
            refresh_token_hash,
            platform: platform.to_string(),
            device_info: Some(device_info.to_string()),
            ip_address: ip,
            expires_at,
        })
        .await?;

    Ok(pair)
}

/// Upsert every submitted asset key for `user_id`. Idempotent (the DB upsert
/// keys on `(user_id, asset, key_type)`), so it is safe to call on first
/// creation, on re-registration of the same pubkey, and on a proven rotation.
async fn upsert_all_keys(
    state: &AppState,
    user_id: Uuid,
    keys: &[AssetPublicKey],
) -> Result<(), AppError> {
    for key in keys {
        let asset = parse_asset(&key.asset)?;
        state
            .db
            .upsert_user_key(NewUserKey {
                user_id,
                asset,
                public_key: key.public_key.clone(),
                public_spend_key: key.public_spend_key.clone(),
                key_type: "primary".to_string(),
            })
            .await?;
    }
    Ok(())
}

// ── POST /auth/pow-challenge ─────────────────────────────────────────────────

/// Issue a fresh proof-of-work challenge for the wallet to solve before calling
/// `/auth/extension`. The solved payload is sent back as the request's
/// `altcha_solution`.
///
/// Stateless: the challenge embeds an HMAC signature over its own fields plus an
/// expiry, so no issued-challenge store is needed. See [`crate::core::pow`].
#[utoipa::path(
    post,
    path = "/auth/pow-challenge",
    responses((status = 200, description = "Proof-of-work challenge for wallet registration")),
    tag = "auth"
)]
#[instrument(skip(state))]
pub async fn pow_challenge(
    State(state): State<Arc<AppState>>,
) -> Result<Json<altcha::Challenge>, AppError> {
    let challenge = crate::core::pow::issue_challenge(&state.config.pow)?;
    Ok(Json(challenge))
}

// ── POST /auth/extension ─────────────────────────────────────────────────────

/// Register a new extension wallet or re-authenticate an existing one.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ExtensionRegisterRequest {
    /// Public keys for each supported asset. A `btc` key is required (it is the
    /// identity).
    pub keys: Vec<AssetPublicKey>,
    /// Optional reserved username.
    pub username: Option<String>,
    /// Wallet creation time (unix seconds), to bound chain scans.
    pub wallet_birthday: Option<i64>,
    /// Seed fingerprint `hex(SHA256(SHA256(seed))[..])`. Used for restore and to
    /// LOCATE a candidate user row for the derivation-rotation path. By itself it
    /// is NOT authority: a rotation also requires `rotation_signature` below.
    pub seed_fingerprint: Option<String>,
    pub xmr_start_height: Option<i64>,
    pub wow_start_height: Option<i64>,
    /// Unix seconds that were signed to prove BTC key ownership.
    pub signed_timestamp: i64,
    /// BIP-137 base64 signature of `smirk-auth-{signed_timestamp}` under the
    /// SUBMITTED (new) BTC key. Proves control of the key in `keys`.
    pub signature: String,
    /// Derivation-rotation proof: BIP-137 base64 signature of the SAME
    /// `smirk-auth-{signed_timestamp}` message under the BTC key ALREADY ON FILE
    /// for the user identified by `seed_fingerprint`. Required to re-point an
    /// existing user row; without it (or if it does not verify against the stored
    /// key) a fingerprint match is treated as a brand-new identity and the
    /// existing row is never touched. See [`extension_register`].
    #[serde(default)]
    pub rotation_signature: Option<String>,
    /// Optional proof-of-work solution. Required when the PoW gate applies to
    /// this pubkey (see [`pow_applies`]); otherwise ignored.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub altcha_solution: Option<altcha::Payload>,
}

/// Register a new extension wallet or authenticate an existing one.
///
/// The BTC pubkey hash is the unique identity. A signed timestamp proves control
/// of the BTC private key (defeats registration with a stolen public key). When
/// the PoW gate applies and the wallet is new, a valid `altcha_solution` is
/// required; a returning user (a known `pubkey_hash`) bypasses PoW.
///
/// ## Derivation rotation is authenticated (account-takeover defense)
///
/// A known `seed_fingerprint` at a NEW `pubkey_hash` (the wallet changed its
/// derivation scheme) may re-point the existing user row — but ONLY when the
/// request also carries a `rotation_signature` that verifies against the BTC key
/// already on file for that user (proving control of the seed-derived key, not
/// merely knowledge of the fingerprint, which `check_restore` discloses and is
/// not secret). A bare fingerprint match WITHOUT a valid rotation proof is
/// treated as a brand-new identity: a fresh user row is created on the new
/// `pubkey_hash` and the matched victim row is never modified. The rotation path
/// is gated by PoW exactly like any other new-pubkey registration.
#[utoipa::path(
    post,
    path = "/auth/extension",
    request_body = ExtensionRegisterRequest,
    responses((status = 200, description = "Wallet registered or authenticated", body = AuthResponse)),
    tag = "auth"
)]
#[instrument(skip(state, headers, req, peer))]
pub async fn extension_register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ExtensionRegisterRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let ip = client_ip(&state, &headers, peer);

    // The BTC key is the identity. Resolve it (and its hash) first: needed for
    // the PoW gate, the returning-user check, and the signature verification.
    let btc_key = req
        .keys
        .iter()
        .find(|k| k.asset.eq_ignore_ascii_case("btc"))
        .ok_or_else(|| AppError::ValidationError("BTC public key is required".into()))?;
    let pubkey_hash = hash_public_key(&btc_key.public_key);
    let pubkey_hash_lc = pubkey_hash.to_lowercase();

    if let Some(ref username) = req.username {
        validate_username(username)?;
    }

    // Prove control of the SUBMITTED BTC private key: a fresh, signed timestamp.
    // This is required on every path; it proves the caller controls the key in
    // `keys`, but NOT (on its own) any key already on file for another user.
    let now = Utc::now().timestamp();
    if (now - req.signed_timestamp).abs() > SIGNED_TS_MAX_DRIFT_SECS {
        return Err(AppError::ValidationError(
            "Signed timestamp expired or too far in the future".into(),
        ));
    }
    let message = format!("smirk-auth-{}", req.signed_timestamp);
    // `verify_bitcoin_signature` returns Ok(()) ONLY on a valid signature; a
    // bad signature is an AuthError, a malformed one a ValidationError — both
    // literal-messaged, so this is not an oracle.
    verify_bitcoin_signature(&message, &req.signature, &btc_key.public_key)?;

    // Is the exact pubkey_hash already known? (Plain returning user.)
    let returning_by_pubkey = state
        .db
        .get_user_by_pubkey_hash(&pubkey_hash)
        .await?
        .is_some();

    let wallet_birthday = req
        .wallet_birthday
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

    // ── Authenticated derivation-rotation path ──────────────────────────────
    //
    // A known fingerprint at a NEW pubkey_hash. We re-point the existing user row
    // ONLY if the request proves control of the BTC key ALREADY ON FILE for that
    // user (the seed can re-derive it). Otherwise we DO NOT touch that row.
    if !returning_by_pubkey {
        if let Some(ref fp) = req.seed_fingerprint {
            if let Some(target) = state.db.get_user_by_seed_fingerprint(fp).await? {
                // Fetch the BTC key on file for the matched user. Absence means
                // we cannot authenticate a rotation -> fall through to new-identity.
                let stored_btc = state.db.get_user_key(target.id, AssetType::Btc).await?;

                let rotation_proven = match (&req.rotation_signature, &stored_btc) {
                    (Some(sig), Some(stored)) => {
                        // Control of the on-file (seed-derived) key proves seed
                        // ownership. A bad signature is rejected (not an oracle:
                        // we simply decline to rotate and create a new identity).
                        verify_bitcoin_signature(&message, sig, &stored.public_key).is_ok()
                    }
                    _ => false,
                };

                if rotation_proven {
                    // PoW still applies to the new pubkey, exactly like any other
                    // new-pubkey registration.
                    enforce_pow(&state, &pubkey_hash_lc, false, req.altcha_solution.as_ref())?;

                    info!(user_id = %target.id, "auto key-rotation: fingerprint match + rotation proof verified");
                    state.db.update_pubkey_hash(target.id, &pubkey_hash).await?;
                    upsert_all_keys(&state, target.id, &req.keys).await?;

                    let pair = issue_session(
                        &state,
                        target.id,
                        Platform::Extension,
                        "Browser Extension",
                        Some(IpNetwork::from(ip)),
                    )
                    .await?;
                    let _ = state
                        .db
                        .record_login_event(
                            Some(target.id),
                            "btc",
                            Platform::Extension.as_str(),
                            None,
                            Some(&ip.to_string()),
                        )
                        .await;
                    return Ok(Json(AuthResponse {
                        access_token: pair.access_token,
                        refresh_token: pair.refresh_token,
                        expires_in: pair.expires_in,
                        user: user_info(&target),
                        is_new: false,
                    }));
                }

                // Fingerprint matched but rotation was NOT proven. Do not touch
                // the existing row; fall through and create a brand-new identity
                // on the submitted pubkey_hash. We must NOT carry the matched
                // user's seed_fingerprint onto the new row (the UNIQUE constraint
                // would collide and could leak existence), so drop it below.
                warn!(
                    "extension_register: fingerprint match WITHOUT valid rotation proof; \
                     treating as a new identity (existing row untouched)"
                );
            }
        }
    }

    // ── Plain get-or-create on the submitted pubkey_hash ────────────────────
    //
    // Either a known pubkey (returning) or a genuinely new identity. PoW applies
    // to new pubkeys only.
    enforce_pow(
        &state,
        &pubkey_hash_lc,
        returning_by_pubkey,
        req.altcha_solution.as_ref(),
    )?;

    // If we reached here after an unproven fingerprint match, do NOT attach that
    // fingerprint to the new row — it belongs to another user, and the UNIQUE
    // constraint would either collide or hijack the lookup. Only attach the
    // fingerprint when it is genuinely unknown, or when this is the same pubkey
    // (a plain returning user, where get_or_create only backfills NULLs anyway).
    let fingerprint_for_row = match &req.seed_fingerprint {
        Some(fp) => {
            let belongs_to_other =
                !returning_by_pubkey && state.db.get_user_by_seed_fingerprint(fp).await?.is_some();
            if belongs_to_other {
                None
            } else {
                Some(fp.clone())
            }
        }
        None => None,
    };

    let user = state
        .db
        .get_or_create_user_by_pubkey_hash(
            &pubkey_hash,
            req.username.clone(),
            wallet_birthday,
            fingerprint_for_row,
            req.xmr_start_height,
            req.wow_start_height,
        )
        .await?;

    // Derive is_new from the resolved row, not the pre-read: a concurrent
    // first-registration race is settled in the DB. `created_at == updated_at`
    // on a freshly-inserted row and diverges on the COALESCE backfill update or
    // any later write, so it is a reliable "created just now" marker.
    let is_new = user.created_at == user.updated_at && !returning_by_pubkey;

    // Upsert keys unconditionally: idempotent, and this honors asset-key rotation
    // when a returning user re-registers with an updated key.
    upsert_all_keys(&state, user.id, &req.keys).await?;

    if is_new {
        info!(user_id = %user.id, num_keys = req.keys.len(), "registered new extension user");
    } else {
        info!(user_id = %user.id, "existing extension user authenticated");
    }

    let pair = issue_session(
        &state,
        user.id,
        Platform::Extension,
        "Browser Extension",
        Some(IpNetwork::from(ip)),
    )
    .await?;
    let _ = state
        .db
        .record_login_event(
            Some(user.id),
            "btc",
            Platform::Extension.as_str(),
            None,
            Some(&ip.to_string()),
        )
        .await;

    Ok(Json(AuthResponse {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        expires_in: pair.expires_in,
        user: user_info(&user),
        is_new,
    }))
}

/// Enforce the PoW gate for a registration.
///
/// * `returning` users bypass PoW.
/// * For a new pubkey, when [`pow_applies`] a valid solution is REQUIRED.
/// * When PoW does not apply but a solution is supplied, it is still verified so
///   a malformed solution surfaces a clear error (but absence is not rejected).
///
/// `pow_applies` already fail-closes the `FEATURE_POW=false` case, so
/// `verify_payload` (and thus the HMAC key) is never exercised while the feature
/// is disabled.
fn enforce_pow(
    state: &AppState,
    pubkey_hash_lc: &str,
    returning: bool,
    solution: Option<&altcha::Payload>,
) -> Result<(), AppError> {
    if returning {
        info!(pow = "bypass_returning", "returning user, PoW not required");
        return Ok(());
    }
    if pow_applies(state, pubkey_hash_lc) {
        let solution = solution.ok_or_else(|| {
            warn!(
                pow = "missing",
                "PoW required for new wallet but no solution"
            );
            AppError::ValidationError(
                "Proof-of-work solution is required to create a new wallet. \
                 Please upgrade to a newer Smirk client."
                    .into(),
            )
        })?;
        crate::core::pow::verify_payload(&state.config.pow, solution)?;
        info!(pow = "ok", "PoW solution accepted (new user)");
    } else if let Some(solution) = solution {
        // Supplied but not required: verify anyway (clear error on malformed),
        // but only if the feature is enabled so we never touch an empty key.
        if state.config.pow.enabled {
            crate::core::pow::verify_payload(&state.config.pow, solution)?;
        }
    }
    Ok(())
}

/// SHA-256 hex of a public key string — the wallet's stable identity handle.
fn hash_public_key(public_key: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(public_key.as_bytes()))
}

// ── POST /auth/check-restore ─────────────────────────────────────────────────

/// Ask whether a wallet (by seed fingerprint) was created on this backend, and
/// whether the submitted keys match.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CheckRestoreRequest {
    /// Seed fingerprint (16 or 64 hex chars).
    pub fingerprint: String,
    /// Submitted per-asset public keys, for verification.
    pub keys: Vec<AssetPublicKey>,
}

/// Restore-check result. Constant-shape: the same fields are always present so
/// the response is not a structure oracle, and `user_id` is never returned (no
/// enumeration).
///
/// NOTE: `exists` is an INTENTIONAL disclosure (the wallet uses it to decide
/// whether to offer a restore). It is throttled per fingerprint AND per IP, and
/// nothing downstream treats fingerprint-existence as authority — the
/// derivation-rotation path in [`extension_register`] requires a key-control
/// proof, not a bare fingerprint.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CheckRestoreResponse {
    /// Whether the fingerprint exists on this backend.
    pub exists: bool,
    /// Whether every submitted key matches the stored key. `None` when the
    /// fingerprint does not exist.
    pub keys_valid: Option<bool>,
    /// XMR scan-start height, if the wallet was created here.
    pub xmr_start_height: Option<i64>,
    /// WOW scan-start height, if the wallet was created here.
    pub wow_start_height: Option<i64>,
}

/// Check whether a wallet restore is valid (created here + keys match).
///
/// Two governors run BEFORE any user lookup: a per-IP limit
/// ([`RESTORE_IP_THRESHOLD`]) that bounds distinct-fingerprint scanning, and a
/// per-fingerprint failure limit ([`RESTORE_FAIL_THRESHOLD`]); either trips a
/// 429. The per-IP limit uses [`client_ip`] so an untrusted `X-Forwarded-For`
/// cannot evade it. Every attempt is recorded (peppered fingerprint, salted IP).
///
/// The known/unknown branches are equalized: the unknown branch runs the same
/// key-comparison loop against an empty stored set, so the two paths do the same
/// work and the response does not become a timing oracle for existence beyond the
/// already-intentional `exists` field.
#[utoipa::path(
    post,
    path = "/auth/check-restore",
    request_body = CheckRestoreRequest,
    responses((status = 200, description = "Restore validation result", body = CheckRestoreResponse)),
    tag = "auth"
)]
#[instrument(skip(state, headers, req, peer))]
pub async fn check_restore(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CheckRestoreRequest>,
) -> Result<Json<CheckRestoreResponse>, AppError> {
    let ip = client_ip(&state, &headers, peer).to_string();

    let valid_hex = req.fingerprint.chars().all(|c| c.is_ascii_hexdigit());
    let valid_len = req.fingerprint.len() == 16 || req.fingerprint.len() == 64;
    if !valid_hex || !valid_len {
        return Err(AppError::ValidationError(
            "Invalid fingerprint format (expected 16 or 64 hex characters)".into(),
        ));
    }

    // Per-IP governor FIRST: bounds distinct-fingerprint enumeration that the
    // per-fingerprint counter cannot see (each candidate is probed once).
    let ip_attempts = state.db.count_ip_restore_attempts(&ip).await?;
    if ip_attempts >= RESTORE_IP_THRESHOLD {
        warn!(
            ip_attempts,
            "restore blocked: too many attempts from this IP"
        );
        return Err(AppError::RateLimited);
    }

    // Per-fingerprint failure governor.
    let failed = state
        .db
        .count_failed_restore_attempts(&req.fingerprint)
        .await?;
    if failed >= RESTORE_FAIL_THRESHOLD {
        warn!(failed, "restore blocked: too many failed attempts");
        return Err(AppError::RateLimited);
    }

    let user = state
        .db
        .get_user_by_seed_fingerprint(&req.fingerprint)
        .await?;

    // Equalize work across branches: always fetch the stored keys (an empty set
    // for an unknown fingerprint) and always run the comparison loop, so the
    // unknown and known paths do the same DB + CPU work.
    let stored = match &user {
        Some(u) => state.db.get_user_keys(u.id).await?,
        None => Vec::new(),
    };

    let mut all_match = !req.keys.is_empty();
    for submitted in &req.keys {
        let Ok(asset) = parse_asset(&submitted.asset) else {
            all_match = false;
            continue;
        };
        match stored.iter().find(|k| k.asset == asset) {
            Some(k) if k.public_key == submitted.public_key => {}
            _ => all_match = false,
        }
    }

    match user {
        None => {
            // Unknown fingerprint -> a failed attempt; same response shape as a
            // found-but-mismatch (sans heights).
            let _ = state
                .db
                .record_restore_attempt(&req.fingerprint, Some(&ip), false)
                .await;
            Ok(Json(CheckRestoreResponse {
                exists: false,
                keys_valid: None,
                xmr_start_height: None,
                wow_start_height: None,
            }))
        }
        Some(user) => {
            let _ = state
                .db
                .record_restore_attempt(&req.fingerprint, Some(&ip), all_match)
                .await;
            Ok(Json(CheckRestoreResponse {
                exists: true,
                keys_valid: Some(all_match),
                xmr_start_height: user.xmr_start_height,
                wow_start_height: user.wow_start_height,
            }))
        }
    }
}

// ── POST /auth/refresh ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Rotate a refresh token.
///
/// Verifies the JWT, then re-looks-up the ACTIVE session by peppered hash
/// (`get_session_by_token_hash` already filters revoked/expired) — a missing row
/// means the token was revoked, expired, or already rotated, and is rejected.
/// The session's `user_id` is asserted equal to the JWT `sub` (defense-in-depth
/// against any future token-confusion class). The old session is revoked and a
/// fresh pair issued (revoke-then-issue); the `revoke_session` race-loser also
/// rejects, so a stolen token cannot be reused.
#[utoipa::path(
    post,
    path = "/auth/refresh",
    request_body = RefreshTokenRequest,
    responses((status = 200, description = "Token refreshed", body = AuthResponse)),
    tag = "auth"
)]
#[instrument(skip(state, req))]
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let (user_id, _sid) = state.sessions.verify_refresh_token(&req.refresh_token)?;

    let token_hash = hash_refresh_token(
        &req.refresh_token,
        &state.config.secrets.refresh_token_pepper,
    );
    let session = state
        .db
        .get_session_by_token_hash(&token_hash)
        .await?
        .ok_or_else(|| AppError::AuthError("Invalid or expired token".into()))?;

    // Defense-in-depth: the JWT subject must match the session owner. With the
    // current minting these cannot diverge (the hash is of the same token whose
    // sub we read), but assert the invariant so a future hashing/minting change
    // can never issue a session for the wrong user.
    if session.user_id != user_id {
        warn!("refresh: JWT sub does not match session user_id; rejecting");
        return Err(AppError::AuthError("Invalid or expired token".into()));
    }

    let user = state
        .db
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| AppError::AuthError("Invalid or expired token".into()))?;

    // Preserve the originating platform across rotation.
    let platform: Platform = session.platform.parse()?;

    // Revoke the old session FIRST. If it was already revoked (concurrent
    // refresh / replay), reject — never issue a second live pair for one token.
    if !state.db.revoke_session(session.id).await? {
        return Err(AppError::AuthError("Invalid or expired token".into()));
    }

    let pair = issue_session(
        &state,
        user.id,
        platform,
        session.device_info.as_deref().unwrap_or("unknown"),
        session.ip_address,
    )
    .await?;

    state.db.update_user_last_seen(user.id).await?;
    info!(user_id = %user.id, "token refreshed");

    Ok(Json(AuthResponse {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        expires_in: pair.expires_in,
        user: user_info(&user),
        is_new: false,
    }))
}

// ── POST /auth/logout ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LogoutResponse {
    pub success: bool,
}

/// Revoke the session backing a refresh token. Idempotent: an unknown or
/// already-revoked token still returns success (logout should never error).
#[utoipa::path(
    post,
    path = "/auth/logout",
    request_body = LogoutRequest,
    responses((status = 200, description = "Session revoked", body = LogoutResponse)),
    tag = "auth"
)]
#[instrument(skip(state, req))]
pub async fn logout(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LogoutRequest>,
) -> Result<Json<LogoutResponse>, AppError> {
    let token_hash = hash_refresh_token(
        &req.refresh_token,
        &state.config.secrets.refresh_token_pepper,
    );
    if let Some(session) = state.db.get_session_by_token_hash(&token_hash).await? {
        let _ = state.db.revoke_session(session.id).await;
        info!(session_id = %session.id, "session revoked via logout");
    }
    Ok(Json(LogoutResponse { success: true }))
}

// ── GET /auth/me ─────────────────────────────────────────────────────────────

/// The authenticated user's own info.
#[utoipa::path(
    get,
    path = "/auth/me",
    responses(
        (status = 200, description = "Current authenticated user", body = UserInfo),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "auth"
)]
#[instrument(skip(state, headers))]
pub async fn get_me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<UserInfo>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    let user = state
        .db
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| AppError::AuthError("Invalid or expired token".into()))?;
    Ok(Json(user_info(&user)))
}

// ── POST /auth/nostr (NIP-98 login) ──────────────────────────────────────────

/// Sign in with a Nostr identity (NIP-98 HTTP Auth, login grade).
///
/// The `Nostr <base64(event)>` token is read from the `Authorization` header and
/// verified against the canonical `config.identity.public_api_url` + `/auth/nostr`
/// (never the request Host). The npub must ALREADY be linked to a user (see
/// [`nostr_link`]); this endpoint NEVER creates a user — an unlinked npub is 401.
#[utoipa::path(
    post,
    path = "/auth/nostr",
    responses(
        (status = 200, description = "Session for the linked Nostr identity", body = AuthResponse),
        (status = 401, description = "Invalid NIP-98 token or no linked account")
    ),
    tag = "auth"
)]
#[instrument(skip(state, headers, peer))]
pub async fn nostr_login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<AuthResponse>, AppError> {
    let ip = client_ip(&state, &headers, peer);

    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::AuthError("Missing authorization header".into()))?;

    let url = nip98_url(&state, "/auth/nostr")?;
    let pubkey = verify_nip98(
        auth,
        &url,
        "POST",
        Utc::now().timestamp(),
        NIP98_LOGIN_MAX_AGE_SECS,
    )
    .map_err(|_| AppError::AuthError("Invalid Nostr auth".into()))?;

    // Resolve to an existing user only. Never create.
    let user = state
        .db
        .find_user_by_nostr_pubkey(&pubkey)
        .await?
        .ok_or_else(|| {
            AppError::AuthError(
                "No account is linked to this Nostr identity. Link it from a signed-in session first."
                    .into(),
            )
        })?;

    let pair = issue_session(
        &state,
        user.id,
        Platform::Nostr,
        "Nostr",
        Some(IpNetwork::from(ip)),
    )
    .await?;
    let _ = state
        .db
        .record_login_event(
            Some(user.id),
            "btc",
            Platform::Nostr.as_str(),
            None,
            Some(&ip.to_string()),
        )
        .await;

    info!(user_id = %user.id, "authenticated via Nostr (NIP-98)");
    Ok(Json(AuthResponse {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        expires_in: pair.expires_in,
        user: user_info(&user),
        is_new: false,
    }))
}

// ── POST /auth/nostr/link (state change) ─────────────────────────────────────

/// Link a Nostr identity to the authenticated user. This is a STATE CHANGE, so
/// it carries a signed-action proof, not a login-grade token.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct NostrLinkRequest {
    /// The `Nostr <base64(event)>` signed-action token proving control of the
    /// npub AND committing to the server nonce + this request.
    pub nostr_token: String,
    /// The server-issued single-use nonce the signed action must bind (the
    /// event's `challenge` tag).
    pub nonce: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct NostrLinkResponse {
    /// The linked x-only Nostr pubkey (hex).
    pub nostr_pubkey: String,
}

/// Link a Nostr identity (npub) to the authenticated user.
///
/// Dual auth: the Bearer JWT identifies the user; a NIP-98 *signed-action* proof
/// (not a login token) proves control of the npub AND binds a server-issued
/// single-use `nonce`, the purpose `nostr_link`, and this exact request via the
/// request-descriptor hash. On success the npub is stored so a later
/// [`nostr_login`] resolves to the same wallet; a collision is 409.
///
/// ## Descriptor binding is a CONTRACT (not an implementation detail)
///
/// The `payload` tag binds `descriptor_sha256(request_descriptor("POST",
/// "/api/v1/auth/nostr/link", "", b""))` — an EMPTY body hash, with no query.
/// The JSON `{nostr_token, nonce}` rides in the HTTP body but is deliberately NOT
/// part of the signed descriptor (it carries the proof itself, so it cannot also
/// be inside it). The wallet MUST build the identical descriptor. This exact
/// method/path/query/empty-body shape is a cross-impl contract and must be pinned
/// in a shared test vector (mirroring the nip98.rs interop test) before
/// `consume_link_nonce` is un-stubbed — otherwise the binding silently breaks or
/// weakens at integration time.
///
/// TODO(operator-surface): the server-nonce *issue* (`GET
/// /auth/nostr/link-challenge`, rand 32 bytes, stored) + the ATOMIC single-use
/// *consume* (a `DELETE ... WHERE nonce=$1 RETURNING` so a replay loses the race,
/// never check-then-delete), plus the wallet's signed-action token builder, are
/// wired in the operator-surface phase. Until then [`consume_link_nonce`] always
/// returns `false` and this handler FAILS CLOSED: it validates the full proof
/// shape but refuses every link, because it cannot yet prove the nonce was issued
/// by this server and is unused.
#[utoipa::path(
    post,
    path = "/auth/nostr/link",
    request_body = NostrLinkRequest,
    responses(
        (status = 200, description = "Linked npub", body = NostrLinkResponse),
        (status = 401, description = "Invalid proof or missing session"),
        (status = 409, description = "npub already linked to another account")
    ),
    tag = "auth"
)]
#[instrument(skip(state, headers, req))]
pub async fn nostr_link(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<NostrLinkRequest>,
) -> Result<Json<NostrLinkResponse>, AppError> {
    // 1. JWT identifies the acting user.
    let user_id = extract_user_id_from_token(&state, &headers).await?;

    // 2. Atomically consume the server-issued nonce. FAIL CLOSED: the
    // issue/consume store is not wired until the operator-surface phase, so
    // `consume_link_nonce` currently always returns false and every request is
    // rejected here. This is intentional — better to refuse links than to accept
    // a proof whose nonce we cannot prove we issued + has not been replayed.
    if !consume_link_nonce(&state, &req.nonce).await {
        warn!("nostr_link: nonce not recognized / store not wired — refusing (fail-closed)");
        return Err(AppError::AuthError("Invalid or expired nonce".into()));
    }

    // 3. Verify the signed-action proof binds the nonce, purpose, and this
    // request. The descriptor binds method+path+query+body-hash; the body hash is
    // of an EMPTY body by contract (see the doc comment) — the wallet builds the
    // identical descriptor.
    let url = nip98_url(&state, "/auth/nostr/link")?;
    let descriptor = request_descriptor("POST", "/api/v1/auth/nostr/link", "", b"");
    let payload_sha256 = descriptor_sha256(&descriptor);
    let pubkey = verify_signed_action(
        &req.nostr_token,
        &url,
        "POST",
        "nostr_link",
        &req.nonce,
        &payload_sha256,
        None,
        None,
        Utc::now().timestamp(),
        NIP98_ACTION_MAX_AGE_SECS,
    )
    .map_err(|_| AppError::AuthError("Invalid Nostr proof".into()))?;

    // 4. Persist. UNIQUE collision -> 409 CONFLICT (handled in set_nostr_pubkey).
    state.db.set_nostr_pubkey(user_id, &pubkey).await?;
    info!(user_id = %user_id, "linked Nostr identity");
    Ok(Json(NostrLinkResponse {
        nostr_pubkey: pubkey,
    }))
}

/// Atomically consume a server-issued single-use link nonce.
///
/// TODO(operator-surface): back this with the shared challenge store — issue on a
/// `GET /auth/nostr/link-challenge` (rand 32 bytes, stored), and consume here via
/// an ATOMIC single-use delete (`DELETE ... WHERE nonce=$1 RETURNING`) so a
/// replay loses the race. Until then it returns `false` so [`nostr_link`] fails
/// closed — no nonce can be accepted that we cannot prove we issued.
async fn consume_link_nonce(_state: &AppState, _nonce: &str) -> bool {
    false
}

// ── router ───────────────────────────────────────────────────────────────────

/// Auth routes, RELATIVE to the `/api/v1` mount point. The application is
/// expected to `Router::new().nest("/api/v1", auth::routes())` and serve with
/// `into_make_service_with_connect_info::<SocketAddr>()` so [`client_ip`] sees
/// the real TCP peer.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/extension", post(extension_register))
        .route("/auth/check-restore", post(check_restore))
        .route("/auth/pow-challenge", post(pow_challenge))
        .route("/auth/refresh", post(refresh_token))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(get_me))
        .route("/auth/nostr", post(nostr_login))
        .route("/auth/nostr/link", post(nostr_link))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_parse_roundtrips_and_rejects() {
        assert_eq!(parse_asset("BTC").unwrap(), AssetType::Btc);
        assert_eq!(parse_asset("grin").unwrap(), AssetType::Grin);
        assert!(parse_asset("doge").is_err());
    }

    #[test]
    fn username_rules() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("a_b_2").is_ok());
        assert!(validate_username("ab").is_err()); // too short
        assert!(validate_username("_alice").is_err()); // leading underscore
        assert!(validate_username("alice_").is_err()); // trailing underscore
        assert!(validate_username("Alice").is_err()); // uppercase
        assert!(validate_username("al ice").is_err()); // space
    }

    #[test]
    fn hash_public_key_is_stable_hex() {
        let a = hash_public_key("deadbeef");
        assert_eq!(a, hash_public_key("deadbeef"));
        assert_eq!(a.len(), 64);
        assert_ne!(a, hash_public_key("deadbee0"));
    }

    /// Wire-shape regression: the extension request must accept the wrapped
    /// `altcha::Payload` envelope and reject a bare `Solution`.
    #[test]
    fn extension_request_wire_shape() {
        let wrapped = r#"{
            "keys": [{"asset":"btc","public_key":"deadbeef"}],
            "seed_fingerprint": "fp-1",
            "signed_timestamp": 1700000000,
            "signature": "sig",
            "altcha_solution": {
                "challenge": {
                    "parameters": {
                        "algorithm": "PBKDF2/SHA-256",
                        "cost": 100,
                        "keyLength": 32,
                        "keyPrefix": "00",
                        "nonce": "n",
                        "salt": "s"
                    },
                    "signature": "hmac"
                },
                "solution": { "counter": 42, "derivedKey": "00aabb", "time": 1.0 }
            }
        }"#;
        let req: ExtensionRegisterRequest =
            serde_json::from_str(wrapped).expect("wrapped envelope deserializes");
        assert!(req.altcha_solution.is_some());
        assert!(req.rotation_signature.is_none());

        let bare = r#"{
            "keys": [{"asset":"btc","public_key":"deadbeef"}],
            "signed_timestamp": 1700000000,
            "signature": "sig",
            "altcha_solution": { "counter": 42, "derivedKey": "00aabb" }
        }"#;
        assert!(serde_json::from_str::<ExtensionRegisterRequest>(bare).is_err());
    }

    /// The rotation-proof field is optional and round-trips when present.
    #[test]
    fn extension_request_accepts_rotation_signature() {
        let with_rot = r#"{
            "keys": [{"asset":"btc","public_key":"deadbeef"}],
            "seed_fingerprint": "fp-1",
            "signed_timestamp": 1700000000,
            "signature": "newsig",
            "rotation_signature": "oldsig"
        }"#;
        let req: ExtensionRegisterRequest =
            serde_json::from_str(with_rot).expect("rotation envelope deserializes");
        assert_eq!(req.rotation_signature.as_deref(), Some("oldsig"));
    }
}
