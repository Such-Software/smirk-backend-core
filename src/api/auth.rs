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
use crate::models::db::{AssetType, NewSession, NewUser, NewUserKey};
use crate::AppState;

// ── shared constants ────────────────────────────────────────────────────────

/// Replay window for a NIP-98 LOGIN token (seconds). A captured login token is a
/// bearer credential within this window, so keep it tight — matched to the
/// state-change grade below. Still ample for real client clock skew.
const NIP98_LOGIN_MAX_AGE_SECS: i64 = 30;

/// Replay window for a NIP-98 STATE-CHANGE (signed action) token (seconds).
/// Deliberately tighter than login.
const NIP98_ACTION_MAX_AGE_SECS: i64 = 30;

/// TTL for a Nostr-link nonce (seconds): long enough for the wallet to sign and
/// POST, short enough to bound an unused nonce's lifetime.
const NOSTR_LINK_NONCE_TTL_SECS: i64 = 300;

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

/// Parse the wire key list into the `(AssetType, public_key, public_spend_key)`
/// tuples the atomic-registration DB path binds directly. A bad asset is a 400.
fn parse_keys(
    keys: &[AssetPublicKey],
) -> Result<Vec<(AssetType, String, Option<String>)>, AppError> {
    keys.iter()
        .map(|k| {
            Ok((
                parse_asset(&k.asset)?,
                k.public_key.clone(),
                k.public_spend_key.clone(),
            ))
        })
        .collect()
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
    state.cfg().pow.enabled && crate::core::pow::required_for(&state.cfg().pow, pubkey_hash_lc)
}

/// The canonical absolute URL a NIP-98 token must bind for `path` (the value of
/// the event's `u` tag). Built from `config.identity.public_api_url`, never the
/// request Host. Fail closed when unset (Nostr identity is disabled).
fn nip98_url(state: &AppState, path: &str) -> Result<String, AppError> {
    let cfg = state.cfg();
    let base = cfg.identity.public_api_url.as_deref().ok_or_else(|| {
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
) -> Result<crate::core::session::TokenPair, AppError> {
    let session_id = Uuid::new_v4();
    let pair = state
        .sessions
        .create_token_pair(user_id, platform, session_id)?;

    let refresh_token_hash = hash_refresh_token(
        &pair.refresh_token,
        &state.cfg().secrets.refresh_token_pepper,
    );
    let expires_at = Utc::now() + state.sessions.refresh_token_expiry();

    state
        .db
        .create_session(NewSession {
            id: session_id,
            user_id,
            refresh_token_hash,
            platform: platform.to_string(),
            device_info: Some(device_info.to_string()),
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
    let challenge = crate::core::pow::issue_challenge(&state.cfg().pow)?;
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
    /// Operator-minted invite code. Required when the instance enables the invite
    /// registration gate (see `/capabilities` → `registration.invite_required`);
    /// ignored otherwise and for returning wallets.
    #[serde(default)]
    pub invite_code: Option<String>,
    /// Settled payment-invoice id from `/auth/payment-invoice`. Required when the
    /// instance enables the pay-to-register gate (see `/capabilities` →
    /// `registration.payment_required`); ignored otherwise and for returning
    /// wallets. Its settlement is verified against the processor and the invoice
    /// atomically consumed (single-use) before the wallet is granted.
    #[serde(default)]
    pub payment_invoice_id: Option<String>,
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
                    // new-pubkey registration. The invite and pay-to-register gates
                    // are INTENTIONALLY skipped: this branch only re-points an
                    // already-registered (already-gated) user's row to a new key —
                    // a move, not a mint (`is_new=false`, no new identity) — and is
                    // reachable only by proving control of that user's on-file key.
                    // Do NOT add a create / get-or-create here without also running
                    // enforce_invite + enforce_payment, or it becomes a gate bypass.
                    enforce_pow(&state, &pubkey_hash_lc, false, req.altcha_solution.as_ref())?;

                    info!(user_id = %target.id, "auto key-rotation: fingerprint match + rotation proof verified");
                    state.db.update_pubkey_hash(target.id, &pubkey_hash).await?;
                    upsert_all_keys(&state, target.id, &req.keys).await?;

                    let pair =
                        issue_session(&state, target.id, Platform::Extension, "Browser Extension")
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
    // Never attach a seed_fingerprint that already belongs to ANOTHER user (it
    // would collide on the UNIQUE or hijack the lookup); a returning user only
    // backfills NULLs anyway. Used as the new row's fingerprint below.
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

    let (user, is_new) = if returning_by_pubkey {
        // Returning wallet: no gate token consumed. Backfill optionals + rotate keys
        // through the ordinary path.
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
        upsert_all_keys(&state, user.id, &req.keys).await?;
        (user, false)
    } else {
        // NEW wallet: reject a taken username up front (fast, friendly), then consume
        // the gate token(s) + create the user + persist keys ATOMICALLY. A username
        // collision or a raced token rolls the whole tx back, so a paid invoice /
        // invite is never burned without an account being created.
        ensure_username_available(&state, false, req.username.as_deref()).await?;
        let gates = plan_gate_consume(
            &state,
            &pubkey_hash,
            req.invite_code.as_deref(),
            req.payment_invoice_id.as_deref(),
        )
        .await?;
        let user = state
            .db
            .create_user_consuming_gates(
                gates.invite_code_hash.as_deref(),
                gates
                    .payment
                    .as_ref()
                    .map(|(id, pkh)| (id.as_str(), pkh.as_str())),
                NewUser {
                    username: req.username.clone(),
                    pubkey_hash: Some(pubkey_hash.clone()),
                    nostr_pubkey: None,
                    wallet_birthday,
                    seed_fingerprint: fingerprint_for_row,
                    xmr_start_height: req.xmr_start_height,
                    wow_start_height: req.wow_start_height,
                },
                &parse_keys(&req.keys)?,
            )
            .await?;
        (user, true)
    };

    if is_new {
        info!(user_id = %user.id, num_keys = req.keys.len(), "registered new extension user");
    } else {
        info!(user_id = %user.id, "existing extension user authenticated");
    }

    let pair = issue_session(&state, user.id, Platform::Extension, "Browser Extension").await?;
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
        crate::core::pow::verify_payload(&state.cfg().pow, solution)?;
        info!(pow = "ok", "PoW solution accepted (new user)");
    } else if let Some(solution) = solution {
        // Supplied but not required: verify anyway (clear error on malformed),
        // but only if the feature is enabled so we never touch an empty key.
        if state.cfg().pow.enabled {
            crate::core::pow::verify_payload(&state.cfg().pow, solution)?;
        }
    }
    Ok(())
}

/// What to do about the invite + payment gates for a NEW wallet. The pure
/// decision (no db / async), extracted so the fund-critical one-of dispatch is
/// unit-testable. PoW is handled separately (orthogonal).
#[derive(Debug, PartialEq, Eq)]
enum GatePlan {
    /// No enabled gates — accept (PoW aside).
    Open,
    /// Conjunction: every enabled gate must pass (`all` mode).
    All,
    /// Run only the invite gate.
    Invite,
    /// Run only the payment gate.
    Payment,
    /// `any` mode, both gates enabled, and the client presented BOTH credentials
    /// — reject rather than risk burning two single-use tokens.
    RejectBothPresented,
    /// `any` mode, both gates enabled, but no usable credential presented.
    RequireOne,
}

fn plan_gates(
    mode: crate::config::GateMode,
    require_invite: bool,
    require_payment: bool,
    has_invite: bool,
    has_payment: bool,
) -> GatePlan {
    if !require_invite && !require_payment {
        return GatePlan::Open;
    }
    match mode {
        crate::config::GateMode::All => GatePlan::All,
        crate::config::GateMode::Any => {
            // A single enabled gate under `any` is just that gate.
            if require_invite && !require_payment {
                return GatePlan::Invite;
            }
            if require_payment && !require_invite {
                return GatePlan::Payment;
            }
            // Both enabled => one-of, dispatched by the presented credential.
            match (has_invite, has_payment) {
                (true, true) => GatePlan::RejectBothPresented,
                (true, false) => GatePlan::Invite,
                (false, true) => GatePlan::Payment,
                (false, false) => GatePlan::RequireOne,
            }
        }
    }
}

/// The single-use tokens a NEW registration must consume, resolved from the gate
/// config WITHOUT spending anything. Feeds [`Database::create_user_consuming_gates`],
/// which consumes these AND creates the user in one transaction — so a username
/// collision or a raced token never burns a paid invoice / invite.
struct GatedRegistration {
    /// Hash of the invite code to claim, when the invite gate applies.
    invite_code_hash: Option<String>,
    /// `(invoice_id, pubkey_hash)` to consume, when the payment gate applies.
    payment: Option<(String, String)>,
}

/// Require an invite code and return its hash, erroring if the gate needs one but
/// none was supplied (the presence check + literal the old `enforce_invite` used).
fn require_invite_hash(invite_code: Option<&str>) -> Result<String, AppError> {
    let code = invite_code
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| {
            AppError::ValidationError(
                "An invite code is required to register on this instance.".into(),
            )
        })?;
    Ok(crate::core::invite::hash_invite_code(code))
}

/// Plan (do NOT consume) the gate tokens for a genuinely-NEW wallet, mirroring the
/// pure `plan_gates` decision. The payment invoice's settled-check runs here and is
/// non-consuming, so a still-confirming payment errors BEFORE any token is spent
/// (an invite is never burned on a pending payment — the F3 invariant, now made
/// atomic by consuming both tokens together at creation). Returns the same
/// caller-facing errors the per-gate enforcers did.
async fn plan_gate_consume(
    state: &AppState,
    pubkey_hash: &str,
    invite_code: Option<&str>,
    payment_invoice_id: Option<&str>,
) -> Result<GatedRegistration, AppError> {
    let has_invite = invite_code.map(str::trim).is_some_and(|c| !c.is_empty());
    let has_payment = payment_invoice_id
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());

    match plan_gates(
        state.cfg().registration.gate_mode,
        state.cfg().registration.require_invite,
        state.cfg().registration.payment.require_payment,
        has_invite,
        has_payment,
    ) {
        GatePlan::Open => Ok(GatedRegistration {
            invite_code_hash: None,
            payment: None,
        }),
        GatePlan::All => {
            let invite_code_hash = if state.cfg().registration.require_invite {
                Some(require_invite_hash(invite_code)?)
            } else {
                None
            };
            Ok(GatedRegistration {
                invite_code_hash,
                payment: verify_payment_settled(state, false, pubkey_hash, payment_invoice_id)
                    .await?
                    .map(|id| (id, pubkey_hash.to_string())),
            })
        }
        GatePlan::Invite => Ok(GatedRegistration {
            invite_code_hash: Some(require_invite_hash(invite_code)?),
            payment: None,
        }),
        GatePlan::Payment => Ok(GatedRegistration {
            invite_code_hash: None,
            payment: verify_payment_settled(state, false, pubkey_hash, payment_invoice_id)
                .await?
                .map(|id| (id, pubkey_hash.to_string())),
        }),
        GatePlan::RejectBothPresented => Err(AppError::ValidationError(
            "Present exactly one registration method, not both.".into(),
        )),
        GatePlan::RequireOne => Err(AppError::ValidationError(
            "Registration on this instance requires an invite code or a settled payment. \
             Choose one and retry."
                .into(),
        )),
    }
}

/// Non-consuming half of the pay-to-register gate: confirm the invoice exists,
/// is bound to THIS `pubkey_hash`, is unspent, and reads `Settled` from the
/// processor. Returns `Ok(Some(id))` when ready to consume, `Ok(None)` when the
/// gate does not apply (returning user / gate off). Splitting the check from the
/// consume lets the `all`-mode plan verify payment is settled BEFORE it burns the
/// single-use invite — a pending payment must never cost the invite.
async fn verify_payment_settled(
    state: &AppState,
    returning: bool,
    pubkey_hash: &str,
    payment_invoice_id: Option<&str>,
) -> Result<Option<String>, AppError> {
    if returning || !state.cfg().registration.payment.require_payment {
        return Ok(None);
    }
    // Gate on but no provider built — config validation prevents this, so it is
    // an internal misconfiguration (generic 500), not a client-facing error.
    let provider = state.payment.as_ref().ok_or_else(|| {
        warn!(
            gate = "payment",
            "payment gate on but no provider configured"
        );
        AppError::Internal("payment provider not configured".into())
    })?;

    let id = payment_invoice_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            warn!(
                gate = "payment",
                "payment required for new wallet but no invoice id"
            );
            AppError::ValidationError(
                "Registration on this instance requires payment. Request an invoice from \
                 /auth/payment-invoice, pay it, then retry."
                    .into(),
            )
        })?;

    // Binding precheck against our OWN record. A missing row and a row bound to a
    // DIFFERENT identity collapse to ONE literal — never an oracle distinguishing
    // "unknown" from "someone else's".
    let row = match state.db.get_payment_invoice(id).await? {
        Some(r) if r.pubkey_hash == pubkey_hash => r,
        _ => {
            warn!(
                gate = "payment",
                "unknown or mis-bound payment invoice presented"
            );
            return Err(AppError::ValidationError(
                "Unknown or invalid payment invoice.".into(),
            ));
        }
    };
    if row.consumed_at.is_some() {
        return Err(AppError::ValidationError(
            "This payment invoice has already been used.".into(),
        ));
    }

    // Source of truth: read the processor. Only `Settled` grants — and by the
    // `InvoiceStatus::Settled` adapter contract that means paid IN FULL, so the
    // amount is not re-checked here (it is server-set at mint and the row is the
    // binding anchor; a foreign or underpaid invoice never reaches this point).
    let invoice = provider.get_invoice(id).await?;
    if invoice.status != crate::infra::payment::InvoiceStatus::Settled {
        // Distinct machine-readable code (`PAYMENT_PENDING`) so a polling client
        // can tell "keep waiting" from a terminal failure without matching on the
        // human string.
        return Err(AppError::PaymentPending(
            "Payment not yet confirmed. Complete the payment and retry.".into(),
        ));
    }
    // Defense-in-depth: the processor-side metadata bind, when present, must
    // agree with the row (the row is the authority; this catches a swapped id).
    if let Some(ref bound) = invoice.bind {
        if bound.as_str() != pubkey_hash {
            warn!(gate = "payment", "settled invoice metadata bind mismatch");
            return Err(AppError::ValidationError(
                "Unknown or invalid payment invoice.".into(),
            ));
        }
    }
    Ok(Some(id.to_string()))
}

/// Reject a NEW registration whose requested username is already taken BEFORE any
/// single-use gate token is consumed, so a collision can't burn a paid invoice /
/// invite with no account created. Returning users are exempt (get-or-create
/// only backfills NULL optionals and never re-points an existing username).
///
/// Not fully atomic: a concurrent claim can still race the final `create_user`
/// INSERT between this read and the write. That narrow race is the price of not
/// threading a shared transaction through the gate consume + user INSERT; it is
/// far rarer than a user simply picking an already-taken name, which this closes.
async fn ensure_username_available(
    state: &AppState,
    returning: bool,
    username: Option<&str>,
) -> Result<(), AppError> {
    if returning {
        return Ok(());
    }
    if let Some(name) = username.map(str::trim).filter(|n| !n.is_empty()) {
        if state.db.get_user_by_username(name).await?.is_some() {
            return Err(AppError::Conflict(
                "That username is already taken. Choose another.".into(),
            ));
        }
    }
    Ok(())
}

/// SHA-256 hex of a public key string — the wallet's stable identity handle.
fn hash_public_key(public_key: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(public_key.as_bytes()))
}

// ── POST /auth/payment-invoice ───────────────────────────────────────────────

/// Request a registration-payment invoice for a wallet about to register.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PaymentInvoiceRequest {
    /// The wallet's BTC public key. Its hash is the identity the invoice binds
    /// to; only a later `/auth/extension` proving control of this key can redeem
    /// the settled invoice, so this endpoint needs no separate proof.
    pub btc_public_key: String,
}

/// A created payment invoice: what to pay, and the id to present at registration.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PaymentInvoiceResponse {
    /// Opaque invoice id — send it back as `/auth/extension`'s `payment_invoice_id`.
    pub invoice_id: String,
    /// Where to pay (a hosted checkout URL, or an address).
    pub pay_to: String,
    /// Price to pay.
    pub amount: String,
    /// Price currency.
    pub currency: String,
}

/// Create a registration-payment invoice on the operator's processor.
///
/// Public (pre-registration) and deliberately cheap: it only binds an invoice to
/// the wallet's `pubkey_hash`, which is worthless to anyone who cannot later
/// prove control of that BTC key at `/auth/extension`. The unauthenticated-surface
/// rate limiter bounds invoice spam and unpaid invoices expire on the processor,
/// so no signature proof is required here. Returns 400 when the pay gate is off
/// or the wallet is already registered (it would bypass payment anyway).
#[utoipa::path(
    post,
    path = "/auth/payment-invoice",
    request_body = PaymentInvoiceRequest,
    responses(
        (status = 200, description = "Payment invoice created", body = PaymentInvoiceResponse),
        (status = 400, description = "Pay gate off, already registered, or invalid key"),
        (status = 503, description = "Payment processor unavailable")
    ),
    tag = "auth"
)]
#[instrument(skip(state, req))]
pub async fn payment_invoice(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PaymentInvoiceRequest>,
) -> Result<Json<PaymentInvoiceResponse>, AppError> {
    let cfg = &state.cfg().registration.payment;
    if !cfg.require_payment {
        return Err(AppError::ValidationError(
            "This instance does not require registration payment.".into(),
        ));
    }
    let provider = state.payment.as_ref().ok_or_else(|| {
        warn!(
            gate = "payment",
            "payment gate on but no provider configured"
        );
        AppError::Internal("payment provider not configured".into())
    })?;

    // Light hygiene only (the authoritative key-format check is at
    // /auth/extension): non-empty, bounded, printable — so we don't mint invoices
    // for obvious garbage. A bind to a junk hash is harmless (never redeemable).
    let key = req.btc_public_key.trim();
    if key.is_empty() || key.len() > 200 || !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(AppError::ValidationError("Invalid BTC public key.".into()));
    }
    let pubkey_hash = hash_public_key(key);

    // A known wallet bypasses payment; minting for it would waste the payer's money.
    if state
        .db
        .get_user_by_pubkey_hash(&pubkey_hash)
        .await?
        .is_some()
    {
        return Err(AppError::ValidationError(
            "This wallet is already registered; no payment is required.".into(),
        ));
    }

    let invoice = provider
        .create_invoice(&crate::infra::payment::InvoiceRequest {
            amount: cfg.amount.clone(),
            currency: cfg.currency.clone(),
            confirmations: cfg.confirmations,
            bind: pubkey_hash.clone(),
            expires_minutes: cfg.expires_minutes,
        })
        .await?;

    state
        .db
        .insert_payment_invoice(
            &invoice.id,
            &pubkey_hash,
            provider.kind(),
            &cfg.amount,
            &cfg.currency,
        )
        .await?;

    info!(gate = "payment", "created registration payment invoice");
    Ok(Json(PaymentInvoiceResponse {
        invoice_id: invoice.id,
        pay_to: invoice.pay_to,
        amount: cfg.amount.clone(),
        currency: cfg.currency.clone(),
    }))
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
        &state.cfg().secrets.refresh_token_pepper,
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
        &state.cfg().secrets.refresh_token_pepper,
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
    security(("bearer_auth" = [])),
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

    let pair = issue_session(&state, user.id, Platform::Nostr, "Nostr").await?;
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

// ── GET /auth/nostr/link-challenge (issue the link nonce) ────────────────────

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct NostrLinkChallengeResponse {
    /// Server-issued single-use nonce (hex). The wallet embeds it as the signed
    /// action's `challenge` tag when calling `POST /auth/nostr/link`.
    pub nonce: String,
}

/// Issue a single-use nonce for linking a Nostr identity.
///
/// Authenticated (Bearer JWT). The nonce is bound to the calling user (as the
/// challenge `subject`) and the `nostr_link` purpose, valid for a short TTL, and
/// consumed atomically by [`nostr_link`]. It pairs with the signed-action proof
/// there: the wallet signs an action committing to THIS nonce, so the server can
/// prove the npub-holder authorized the link for THIS account and the request
/// cannot be replayed.
#[utoipa::path(
    security(("bearer_auth" = [])),
    get,
    path = "/auth/nostr/link-challenge",
    responses(
        (status = 200, description = "Single-use link nonce", body = NostrLinkChallengeResponse),
        (status = 401, description = "Missing or invalid session")
    ),
    tag = "auth"
)]
#[instrument(skip(state, headers))]
pub async fn nostr_link_challenge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<NostrLinkChallengeResponse>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    let nonce = state
        .db
        .issue_challenge(
            "nostr_link",
            Some(&user_id.to_string()),
            NOSTR_LINK_NONCE_TTL_SECS,
        )
        .await?;
    Ok(Json(NostrLinkChallengeResponse { nonce }))
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
/// Flow: the wallet first calls `GET /auth/nostr/link-challenge` (authenticated)
/// to obtain a single-use `nonce`, signs an action committing to it, then POSTs
/// here. The nonce is consumed atomically ([`Database::consume_challenge`]) and
/// cross-checked to have been issued to THIS user.
///
/// ## Descriptor binding is a CONTRACT (not an implementation detail)
///
/// The `payload` tag binds `descriptor_sha256(request_descriptor("POST",
/// "/api/v1/auth/nostr/link", "", b""))` — an EMPTY body hash, with no query.
/// The JSON `{nostr_token, nonce}` rides in the HTTP body but is deliberately NOT
/// part of the signed descriptor (it carries the proof itself, so it cannot also
/// be inside it). The wallet MUST build the identical descriptor. This exact
/// method/path/query/empty-body shape is a cross-impl contract, pinned in a shared
/// test vector (`descriptor_sha256` KAT in this file's tests, mirroring the
/// nip98.rs interop test) so the binding cannot silently drift at integration time.
#[utoipa::path(
    security(("bearer_auth" = [])),
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

    // 2. Atomically consume the server-issued nonce (single-use `DELETE …
    // RETURNING`, so a replay loses the race). It was issued to THIS user (subject
    // bound at issue via `/auth/nostr/link-challenge`), so a nonce minted for a
    // different account is rejected. Consume happens BEFORE proof verification, so
    // a failed proof burns the nonce — a legit client simply fetches a fresh one.
    let consumed = state
        .db
        .consume_challenge(&req.nonce, "nostr_link")
        .await?
        .ok_or_else(|| AppError::AuthError("Invalid or expired nonce".into()))?;
    if consumed.subject.as_deref() != Some(user_id.to_string().as_str()) {
        warn!("nostr_link: nonce subject mismatch — refusing (fail-closed)");
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
    // Observability: linking (incl. a rotation that REPLACES an existing npub) is a
    // security-relevant binding change, so record it in the login history — a
    // session-authed rebind should never be silent.
    let _ = state
        .db
        .record_login_event(Some(user_id), "btc", Platform::Nostr.as_str(), None, None)
        .await;
    info!(user_id = %user_id, "linked Nostr identity");
    Ok(Json(NostrLinkResponse {
        nostr_pubkey: pubkey,
    }))
}

// ── GET /auth/nostr/register-challenge (issue the register nonce) ─────────────

/// Issue a single-use nonce for npub-native registration. UNAUTHENTICATED: no
/// user exists yet, so (unlike the link challenge) the nonce is subject-less; the
/// register signed-action binds it purely as replay protection.
#[utoipa::path(
    get,
    path = "/auth/nostr/register-challenge",
    responses((status = 200, description = "Single-use register nonce", body = NostrLinkChallengeResponse)),
    tag = "auth"
)]
#[instrument(skip(state))]
pub async fn nostr_register_challenge(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NostrLinkChallengeResponse>, AppError> {
    let nonce = state
        .db
        .issue_challenge("nostr_register", None, NOSTR_LINK_NONCE_TTL_SECS)
        .await?;
    Ok(Json(NostrLinkChallengeResponse { nonce }))
}

// ── POST /auth/nostr/register (npub-native create) ───────────────────────────

/// Register (or resolve) a wallet keyed by its **Nostr identity**: the
/// self-sovereign, npub-native create path. Unlike [`nostr_login`] (create-never)
/// and [`nostr_link`] (needs a prior BTC-authed JWT), this MINTS a user from the
/// npub alone: no BTC signature is ever required. The npub is the identity anchor;
/// the chain `keys` still ship (for tip addresses + restore) but are NOT the auth
/// proof.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct NostrRegisterRequest {
    /// `Nostr <base64(event)>` signed-action token proving control of the npub AND
    /// binding the server nonce + the `nostr_register` purpose.
    pub nostr_token: String,
    /// The server-issued single-use nonce (from `/auth/nostr/register-challenge`).
    pub nonce: String,
    /// Chain public keys (for tip addresses + restore). A `btc` key is expected
    /// for pay-to-register invoice binding, but it is no longer the identity.
    pub keys: Vec<AssetPublicKey>,
    pub username: Option<String>,
    /// Wallet creation time (unix seconds), to bound chain scans.
    pub wallet_birthday: Option<i64>,
    pub seed_fingerprint: Option<String>,
    pub xmr_start_height: Option<i64>,
    pub wow_start_height: Option<i64>,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub altcha_solution: Option<altcha::Payload>,
    #[serde(default)]
    pub invite_code: Option<String>,
    #[serde(default)]
    pub payment_invoice_id: Option<String>,
}

/// npub-native registration. Verifies a NIP-98 signed-action over a server nonce,
/// re-runs the abuse gates keyed on the npub (a create path must not bypass the
/// PoW/invite/payment gates that `/auth/extension` enforces), then get-or-creates
/// by npub with a `seed_fingerprint` MERGE so a wallet that already has a row
/// (BTC-anchored, or previously linked) is never split into two identities.
///
/// SECURITY NOTE: the proof binds an EMPTY-body descriptor (the same contract as
/// `/auth/nostr/link`), so replay is prevented by the single-use nonce and npub
/// control is proven, but the chain `keys` are TLS-bound rather than
/// proof-bound. Binding the key list into the signed payload is a documented
/// hardening follow-up (defends a TLS-breaking active MITM swapping the keys).
#[utoipa::path(
    post,
    path = "/auth/nostr/register",
    request_body = NostrRegisterRequest,
    responses(
        (status = 200, description = "Wallet registered or authenticated", body = AuthResponse),
        (status = 401, description = "Invalid proof or nonce"),
        (status = 409, description = "Seed already registered under a different Nostr identity")
    ),
    tag = "auth"
)]
#[instrument(skip(state, headers, req, peer))]
pub async fn nostr_register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<NostrRegisterRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let ip = client_ip(&state, &headers, peer);
    if let Some(ref username) = req.username {
        validate_username(username)?;
    }

    // 1. Atomically consume the subject-less register nonce (single-use replay
    //    guard). Consume BEFORE proof verification so a failed proof burns it.
    let _consumed = state
        .db
        .consume_challenge(&req.nonce, "nostr_register")
        .await?
        .ok_or_else(|| AppError::AuthError("Invalid or expired nonce".into()))?;

    // 2. Prove npub control + bind the nonce/purpose. Empty-body descriptor
    //    contract (mirrors /auth/nostr/link). The verifier lowercases the pubkey.
    let url = nip98_url(&state, "/auth/nostr/register")?;
    let descriptor = request_descriptor("POST", "/api/v1/auth/nostr/register", "", b"");
    let payload_sha256 = descriptor_sha256(&descriptor);
    let pubkey = verify_signed_action(
        &req.nostr_token,
        &url,
        "POST",
        "nostr_register",
        &req.nonce,
        &payload_sha256,
        None,
        None,
        Utc::now().timestamp(),
        NIP98_ACTION_MAX_AGE_SECS,
    )
    .map_err(|_| AppError::AuthError("Invalid Nostr proof".into()))?;

    // 3. Returning npub bypasses the abuse gates, exactly like a returning
    //    pubkey_hash on the BTC path.
    let returning = state.db.find_user_by_nostr_pubkey(&pubkey).await?.is_some();

    // 4. Re-run the abuse gates on the npub path; a user-minting endpoint must
    //    not be a gate bypass. PoW keys on the npub (the per-pubkey allowlist is
    //    BTC-only, so only the GLOBAL requirement applies here). Pay-to-register
    //    invoices bind to sha256(btc pubkey), so the payment check still uses the
    //    BTC key carried in `keys` even though it is no longer the identity.
    enforce_pow(&state, &pubkey, returning, req.altcha_solution.as_ref())?;
    // 5. Resolve the user. Returning npub: backfill optionals + rotate keys. New
    //    npub: consume the gate token(s) + create the user + persist keys (tip
    //    addresses / restore anchors) ATOMICALLY, so a username collision or a raced
    //    token never burns a paid invoice / invite without an account.
    let wallet_birthday = req
        .wallet_birthday
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));
    let user = if returning {
        let user = state
            .db
            .get_or_create_user_by_nostr_pubkey(
                &pubkey,
                req.username.clone(),
                wallet_birthday,
                req.seed_fingerprint.clone(),
                req.xmr_start_height,
                req.wow_start_height,
            )
            .await?;
        upsert_all_keys(&state, user.id, &req.keys).await?;
        user
    } else {
        // Fail closed: never bind an npub onto a pre-existing wallet on a
        // seed_fingerprint match alone (this endpoint proves only npub control) —
        // link via the authenticated /auth/nostr/link flow instead.
        if let Some(ref fp) = req.seed_fingerprint {
            if state.db.get_user_by_seed_fingerprint(fp).await?.is_some() {
                return Err(AppError::Conflict(
                    "This wallet already has an account. Sign in with your existing \
                     credentials and link your Nostr identity from settings."
                        .into(),
                ));
            }
        }
        ensure_username_available(&state, false, req.username.as_deref()).await?;
        // Pay-to-register invoices bind to sha256(btc pubkey), so the payment gate
        // keys on the carried BTC key even though the npub is the identity.
        let btc_hash = req
            .keys
            .iter()
            .find(|k| k.asset.eq_ignore_ascii_case("btc"))
            .map(|k| hash_public_key(&k.public_key));
        let gates = plan_gate_consume(
            &state,
            btc_hash.as_deref().unwrap_or(&pubkey),
            req.invite_code.as_deref(),
            req.payment_invoice_id.as_deref(),
        )
        .await?;
        state
            .db
            .create_user_consuming_gates(
                gates.invite_code_hash.as_deref(),
                gates
                    .payment
                    .as_ref()
                    .map(|(id, pkh)| (id.as_str(), pkh.as_str())),
                NewUser {
                    username: req.username.clone(),
                    pubkey_hash: None,
                    nostr_pubkey: Some(pubkey.clone()),
                    wallet_birthday,
                    seed_fingerprint: req.seed_fingerprint.clone(),
                    xmr_start_height: req.xmr_start_height,
                    wow_start_height: req.wow_start_height,
                },
                &parse_keys(&req.keys)?,
            )
            .await?
    };

    // 6. Session.
    let pair = issue_session(&state, user.id, Platform::Nostr, "Nostr").await?;
    let _ = state
        .db
        .record_login_event(
            Some(user.id),
            "nostr",
            Platform::Nostr.as_str(),
            None,
            Some(&ip.to_string()),
        )
        .await;
    info!(user_id = %user.id, is_new = %!returning, "npub-native register/auth (NIP-98)");
    Ok(Json(AuthResponse {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        expires_in: pair.expires_in,
        user: user_info(&user),
        is_new: !returning,
    }))
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
        .route("/auth/payment-invoice", post(payment_invoice))
        .route("/auth/refresh", post(refresh_token))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(get_me))
        .route("/auth/nostr", post(nostr_login))
        .route(
            "/auth/nostr/register-challenge",
            get(nostr_register_challenge),
        )
        .route("/auth/nostr/register", post(nostr_register))
        .route("/auth/nostr/link-challenge", get(nostr_link_challenge))
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

    // ── registration gate composition (plan_gates) ─────────────────────────
    // The pure one-of / conjunction dispatch. Money-safety hinges on `any`
    // mode never planning to run (and thus consume) more than one token.
    mod gate_plan {
        use super::super::{plan_gates, GatePlan};
        use crate::config::GateMode::{All, Any};

        #[test]
        fn no_gates_enabled_is_open_in_either_mode() {
            assert_eq!(plan_gates(All, false, false, false, false), GatePlan::Open);
            assert_eq!(plan_gates(Any, false, false, true, true), GatePlan::Open);
        }

        #[test]
        fn all_mode_is_conjunction_regardless_of_presented_creds() {
            // Both enabled -> All (run both). Single enabled -> still All (the
            // off gate self-disables inside enforce_*).
            assert_eq!(plan_gates(All, true, true, false, false), GatePlan::All);
            assert_eq!(plan_gates(All, true, false, false, false), GatePlan::All);
            assert_eq!(plan_gates(All, false, true, true, true), GatePlan::All);
        }

        #[test]
        fn any_mode_single_gate_is_just_that_gate() {
            assert_eq!(plan_gates(Any, true, false, false, false), GatePlan::Invite);
            assert_eq!(
                plan_gates(Any, false, true, false, false),
                GatePlan::Payment
            );
        }

        #[test]
        fn any_mode_both_enabled_dispatches_on_presented_credential() {
            assert_eq!(plan_gates(Any, true, true, true, false), GatePlan::Invite);
            assert_eq!(plan_gates(Any, true, true, false, true), GatePlan::Payment);
        }

        #[test]
        fn any_mode_rejects_both_credentials_to_avoid_double_consume() {
            // The load-bearing money-safety case: never plan to burn two tokens.
            assert_eq!(
                plan_gates(Any, true, true, true, true),
                GatePlan::RejectBothPresented
            );
        }

        #[test]
        fn any_mode_both_enabled_no_credential_requires_one() {
            assert_eq!(
                plan_gates(Any, true, true, false, false),
                GatePlan::RequireOne
            );
        }
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
