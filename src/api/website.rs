//! Website ("Sign in with your wallet") authentication — the dapp-connect flow.
//!
//! A first-party dapp (smirk.cash, play.wowne.ro, …) lets a user prove control
//! of their Smirk wallet WITHOUT a platform login: the wallet signs a
//! server-issued challenge with its own key material and trades the proof for a
//! standard `(access, refresh)` JWT pair backed by a revocable DB session row —
//! the same session shape as every other login path.
//!
//! Two endpoints, a challenge-response handshake:
//!
//! * [`website_challenge`] — issue a [`WebChallenge`] (a random nonce bound to
//!   the requesting `origin`, with a short TTL) and stash it in
//!   `state.web_challenges`, keyed by its own nonce. The challenge MESSAGE
//!   ([`WebChallenge::message`]) is what the wallet signs.
//! * [`website_verify`] — look the challenge up by nonce, reject it if expired,
//!   verify the wallet's signature over the challenge message with the algorithm
//!   for the submitted asset (BTC/LTC → Bitcoin/BIP-137 ECDSA, XMR/WOW/Grin →
//!   Ed25519), resolve the user from the PROVEN key, mint a `Platform::Web`
//!   session, and CONSUME the challenge so it can never be replayed.
//!
//! ## Security properties
//!
//! * **Single-use.** The challenge is removed from the map at the START of
//!   verify (before any signature work), so a replayed `challenge_id` finds
//!   nothing — even two concurrent verifies race on the `remove` and only one
//!   wins. A failed verify still consumes the challenge (no retry on a stolen
//!   nonce); the wallet re-requests a fresh one.
//! * **Bounded lifetime.** [`WebChallenge`] carries its own expiry; an expired
//!   challenge is rejected even if it is still present in the map.
//! * **No signature-format oracle.** Both verifiers return `Ok(())` ONLY on a
//!   valid signature; a malformed input is a `ValidationError` (400) and a
//!   well-formed-but-wrong signature an `AuthError` (401), both with LITERAL
//!   messages. "User not found" and "signature invalid" deliberately do not
//!   leak which one occurred beyond their distinct, fixed literals.
//! * **No user creation.** Website sign-in resolves an ALREADY-registered
//!   wallet (by the proven identity key's `pubkey_hash`); an unknown key is a
//!   401 directing the user to register with the extension first. It never
//!   mints an identity from a bare signature.
//!
//! Identity in this backend is the wallet's BTC key (`pubkey_hash`); the signed
//! asset's public key is hashed and resolved via
//! [`Database::get_user_by_pubkey_hash`]. The verifier still branches by asset
//! so the cross-asset signing contract holds, but only a key that hashes to a
//! stored identity resolves a user.
//!
//! Routes are registered RELATIVE to `/api/v1` (e.g. `/auth/website/challenge`);
//! see [`routes`]. The app nests this router under `/api/v1`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use chrono::Utc;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

use crate::api::auth::{AuthResponse, UserInfo};
use crate::api::middleware::client_ip;
use crate::core::crypto::signatures::{verify_bitcoin_signature, verify_ed25519_signature};
use crate::core::session::{hash_refresh_token, Platform, WebChallenge};
use crate::error::AppError;
use crate::models::db::{AssetType, NewSession};
use crate::AppState;

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// Request a website-auth challenge for a calling origin.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct WebsiteChallengeRequest {
    /// Origin of the requesting website (e.g. `https://smirk.cash`). Bound into
    /// the challenge message so a signature for one origin is not reusable at
    /// another.
    pub origin: String,
}

/// The challenge to sign, with the handle and expiry the wallet echoes back.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct WebsiteChallengeResponse {
    /// The exact message string to sign with the wallet's key.
    pub challenge: String,
    /// Opaque handle to present at verify time (this is the challenge nonce).
    pub challenge_id: String,
    /// When the challenge expires (RFC 3339).
    pub expires_at: String,
}

/// One asset's signature over the challenge message.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssetSignature {
    /// Asset whose key produced the signature (`btc`, `ltc`, `xmr`, `wow`, `grin`).
    pub asset: String,
    /// Signature over the challenge message. BIP-137 base64 for BTC/LTC; 64-byte
    /// hex Ed25519 for XMR/WOW/Grin.
    pub signature: String,
    /// The public key that produced the signature (format depends on asset).
    pub public_key: String,
}

/// Verify a website-auth challenge with a single asset signature.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct WebsiteVerifyRequest {
    /// The `challenge_id` returned by [`website_challenge`] (the challenge nonce).
    pub challenge_id: String,
    /// The wallet's signature over the challenge message.
    pub signature: AssetSignature,
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Parse an asset string into [`AssetType`], or a literal 400.
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

/// SHA-256 hex of a public key string — the wallet's stable identity handle,
/// computed the same way as the extension-registration path so the two flows
/// resolve to the same user row.
fn hash_public_key(public_key: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(public_key.as_bytes()))
}

/// Verify the challenge signature with the algorithm for `asset`. Returns
/// `Ok(())` ONLY on a cryptographically valid signature; the inner verifiers
/// map malformed input to a literal `ValidationError` (400) and a wrong-but-
/// well-formed signature to a literal `AuthError` (401), so this is not an
/// oracle.
fn verify_asset_signature(
    asset: AssetType,
    message: &str,
    signature: &str,
    public_key: &str,
) -> Result<(), AppError> {
    match asset {
        AssetType::Btc | AssetType::Ltc => verify_bitcoin_signature(message, signature, public_key),
        AssetType::Xmr | AssetType::Wow | AssetType::Grin => {
            verify_ed25519_signature(message, signature, public_key)
        }
    }
}

/// Build [`UserInfo`] from a DB user.
fn user_info(user: &crate::models::db::User) -> UserInfo {
    UserInfo {
        id: user.id.to_string(),
        username: user.username.clone(),
        nostr_pubkey: user.nostr_pubkey.clone(),
    }
}

// ── POST /auth/website/challenge ──────────────────────────────────────────────

/// Issue a website-auth challenge bound to the requesting origin.
///
/// The challenge is stored in `state.web_challenges` keyed by its own nonce and
/// expires shortly (see [`WebChallenge`]). The returned `challenge` message is
/// what the wallet signs; `challenge_id` is the nonce to present at verify.
#[utoipa::path(
    post,
    path = "/auth/website/challenge",
    request_body = WebsiteChallengeRequest,
    responses(
        (status = 200, description = "Website authentication challenge created", body = WebsiteChallengeResponse),
        (status = 400, description = "Invalid origin")
    ),
    tag = "auth"
)]
#[instrument(skip(state, req))]
pub async fn website_challenge(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WebsiteChallengeRequest>,
) -> Result<Json<WebsiteChallengeResponse>, AppError> {
    // Minimal origin sanity check: a non-empty http(s) origin. The value is only
    // ever echoed into the signed message and the login-event record; it is not
    // trusted for any authorization decision.
    if req.origin.is_empty() || !req.origin.starts_with("http") {
        return Err(AppError::ValidationError("Invalid origin".into()));
    }

    let challenge = WebChallenge::new(req.origin);
    // The nonce IS the lookup key, so a verify cannot reference a challenge by a
    // handle the server did not issue.
    let challenge_id = challenge.nonce.clone();
    let challenge_message = challenge.message();
    let expires_at = challenge.expires_at.to_rfc3339();

    {
        let mut challenges = state.web_challenges.write().await;
        challenges.insert(challenge_id.clone(), challenge);
    }

    info!(challenge_id = %challenge_id, "issued website auth challenge");

    Ok(Json(WebsiteChallengeResponse {
        challenge: challenge_message,
        challenge_id,
        expires_at,
    }))
}

// ── POST /auth/website/verify ─────────────────────────────────────────────────

/// Verify a website-auth signature and mint a `Platform::Web` session.
///
/// The challenge is CONSUMED (removed from the map) before any signature work,
/// so it is strictly single-use: a replayed `challenge_id` — or the loser of two
/// concurrent verifies — finds nothing and is rejected. After consume we check
/// expiry, verify the signature over the challenge message with the algorithm
/// for the submitted asset, resolve the ALREADY-registered user by the proven
/// key's `pubkey_hash` (never creating one), and issue a session. All failure
/// messages are literals (no oracle).
#[utoipa::path(
    post,
    path = "/auth/website/verify",
    request_body = WebsiteVerifyRequest,
    responses(
        (status = 200, description = "Website authentication verified; session issued", body = AuthResponse),
        (status = 400, description = "Invalid asset or signature format"),
        (status = 401, description = "Invalid/expired challenge, bad signature, or unknown wallet")
    ),
    tag = "auth"
)]
#[instrument(skip(state, headers, req, peer))]
pub async fn website_verify(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<WebsiteVerifyRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let ip = client_ip(&state, &headers, peer);

    // Consume the challenge FIRST (single-use): remove it before any signature
    // work so a replay — or the loser of a concurrent verify — finds nothing.
    let challenge = {
        let mut challenges = state.web_challenges.write().await;
        challenges.remove(&req.challenge_id).ok_or_else(|| {
            info!("website_verify: challenge not found / already consumed");
            AppError::AuthError("Invalid or expired challenge".into())
        })?
    };

    // Reject an expired challenge even though it was present (and is now gone).
    if challenge.is_expired() {
        info!("website_verify: challenge expired");
        return Err(AppError::AuthError("Invalid or expired challenge".into()));
    }

    // Parse the asset (literal 400 on an unknown asset) and verify the signature
    // over the challenge message with that asset's algorithm. `?` propagates the
    // literal Validation/Auth error from the verifier — never a bool.
    let asset = parse_asset(&req.signature.asset)?;
    let message = challenge.message();
    verify_asset_signature(
        asset,
        &message,
        &req.signature.signature,
        &req.signature.public_key,
    )?;

    // The signature is valid: the caller controls this key. Resolve the
    // ALREADY-registered wallet by the proven key's pubkey hash. We never create
    // a user here — website sign-in is for wallets already registered via the
    // extension. An unknown key is a 401 with a literal, registration-pointing
    // message (the same outcome as a non-matching signature: no enumeration).
    let pubkey_hash = hash_public_key(&req.signature.public_key);
    let user = state
        .db
        .get_user_by_pubkey_hash(&pubkey_hash)
        .await?
        .ok_or_else(|| {
            info!("website_verify: no user for proven key");
            AppError::AuthError(
                "No wallet is registered for this key. Register with the Smirk extension first."
                    .into(),
            )
        })?;

    // Mint a Web session: token pair + revocable DB session row (peppered
    // refresh hash). Mirrors `issue_session` in the auth module so the session
    // shape cannot drift.
    let session_id = uuid::Uuid::new_v4();
    let pair = state
        .sessions
        .create_token_pair(user.id, Platform::Web, session_id)?;
    let refresh_token_hash = hash_refresh_token(
        &pair.refresh_token,
        &state.config.secrets.refresh_token_pepper,
    );
    let expires_at = Utc::now() + state.sessions.refresh_token_expiry();
    state
        .db
        .create_session(NewSession {
            user_id: user.id,
            refresh_token_hash,
            platform: Platform::Web.to_string(),
            device_info: Some("Web Browser".to_string()),
            ip_address: Some(IpNetwork::from(ip)),
            expires_at,
        })
        .await?;

    // Best-effort analytics (which asset signed, from which origin).
    let _ = state
        .db
        .record_login_event(
            Some(user.id),
            asset.as_str(),
            Platform::Web.as_str(),
            Some(&challenge.origin),
            Some(&ip.to_string()),
        )
        .await;
    let _ = state.db.update_user_last_seen(user.id).await;

    info!(user_id = %user.id, asset = %asset, "authenticated via website");

    Ok(Json(AuthResponse {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        expires_in: pair.expires_in,
        user: user_info(&user),
        is_new: false,
    }))
}

// ── router ───────────────────────────────────────────────────────────────────

/// Website-auth routes, RELATIVE to the `/api/v1` mount point. The application
/// is expected to `Router::new().nest("/api/v1", website::routes())` and serve
/// with `into_make_service_with_connect_info::<SocketAddr>()` so [`client_ip`]
/// sees the real TCP peer.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/website/challenge", post(website_challenge))
        .route("/auth/website/verify", post(website_verify))
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
    fn hash_public_key_is_stable_hex() {
        let a = hash_public_key("deadbeef");
        assert_eq!(a, hash_public_key("deadbeef"));
        assert_eq!(a.len(), 64);
        assert_ne!(a, hash_public_key("deadbee0"));
    }

    /// BTC/LTC route through the Bitcoin verifier, XMR/WOW/Grin through Ed25519.
    /// A malformed input must be a `ValidationError` (400), never a silent pass.
    #[test]
    fn verify_asset_signature_routes_by_asset_and_never_passes_garbage() {
        for asset in [AssetType::Btc, AssetType::Ltc] {
            let err = verify_asset_signature(asset, "msg", "not-base64-…", "zz").unwrap_err();
            assert!(matches!(err, AppError::ValidationError(_)));
        }
        for asset in [AssetType::Xmr, AssetType::Wow, AssetType::Grin] {
            let err = verify_asset_signature(asset, "msg", &"00".repeat(64), "zz").unwrap_err();
            assert!(matches!(err, AppError::ValidationError(_)));
        }
    }

    /// Wire-shape regression: the verify request nests a single `AssetSignature`.
    #[test]
    fn verify_request_wire_shape() {
        let body = r#"{
            "challenge_id": "abc123",
            "signature": {
                "asset": "btc",
                "signature": "sig",
                "public_key": "deadbeef"
            }
        }"#;
        let req: WebsiteVerifyRequest =
            serde_json::from_str(body).expect("verify request deserializes");
        assert_eq!(req.challenge_id, "abc123");
        assert_eq!(req.signature.asset, "btc");
    }
}
