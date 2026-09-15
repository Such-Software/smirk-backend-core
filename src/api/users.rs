//! User identity handlers (core).
//!
//! Two concerns live here, both keyed off the wallet's own key material — never a
//! third-party platform login:
//!
//! * **Username** — a reserved `@handle` that backs NIP-05. [`set_username`]
//!   (JWT) claims or updates it (atomically, via the DB UNIQUE constraint, so a
//!   collision is a 409), [`get_my_username`] (JWT) reads the caller's own, and
//!   [`lookup_username`] (public) resolves a handle to its user plus that user's
//!   per-asset receiving public keys.
//! * **Per-asset public keys** — generic public keys a user publishes so others
//!   can send to them. [`register_key`] (JWT) upserts the caller's key for one
//!   asset, [`get_user_keys`] (public) lists a user's keys, and
//!   [`get_user_key_for_asset`] (public) fetches one.
//!
//! Conventions enforced here (matching [`crate::api::auth`]):
//! * JWT-gated handlers resolve the caller via
//!   [`crate::api::middleware::extract_user_id_from_token`]; all failure modes
//!   collapse to a literal `AuthError`, never an oracle.
//! * Username/UNIQUE collisions surface as `AppError::Conflict` (409) — the DB
//!   methods already map the constraint violation; reserved handles are refused
//!   the same way before the DB is touched.
//! * Foreign error detail is routed to tracing by `AppError`; the client gets a
//!   generic literal — SAFE `AppError` messages are literals at the call site.
//! * All request/response fields are snake_case (the wallet client expects it),
//!   and every DTO derives `utoipa::ToSchema`. Assets cross the wire as lowercase
//!   strings (`"btc"`, `"xmr"`, …), parsed/rendered here.
//!
//! Routes are registered RELATIVE to the `/api/v1` mount point; see [`routes`].

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};
use uuid::Uuid;

use crate::api::middleware::extract_user_id_from_token;
use crate::error::AppError;
use crate::models::db::{AssetType, NewUserKey, UserKey};
use crate::AppState;

// ── helpers ─────────────────────────────────────────────────────────────────

/// Usernames reserved to prevent impersonation of the project, staff, or system
/// roles. The candidate is already lowercased before this check.
const RESERVED_USERNAMES: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "support",
    "help",
    "smirk",
    "smirkcash",
    "official",
    "mod",
    "moderator",
    "system",
    "security",
    "team",
    "staff",
    "billing",
    "payment",
    "payments",
    "wallet",
    "info",
    "contact",
    "abuse",
    "noreply",
    "api",
    "www",
    "satoshi",
];

/// Validate a reserved username (3-32 chars, `[a-z0-9_]`, no leading/trailing
/// `_`, not on the reserved list). The candidate must already be lowercased.
///
/// Mirrors [`crate::api::auth`]'s username rules and adds the anti-impersonation
/// reserved-name guard (a 409, the same status a UNIQUE collision yields, so the
/// "taken" and "reserved" outcomes are indistinguishable to a probing client).
///
/// `pub` so the `smirk-admin migrate-legacy` importer applies the identical
/// format + reserved-name rules before it writes a legacy username directly via
/// the DB layer (which bypasses this HTTP handler's checks).
pub fn validate_username(username: &str) -> Result<(), AppError> {
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
    if RESERVED_USERNAMES.contains(&username) {
        return Err(AppError::Conflict("That username is not available".into()));
    }
    Ok(())
}

/// Parse an asset string into [`AssetType`], or a 400. Accepts any case.
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

/// Render a stored [`UserKey`] into its wire DTO.
fn key_info(key: UserKey) -> UserKeyInfo {
    UserKeyInfo {
        asset: key.asset.to_string(),
        public_key: key.public_key,
        public_spend_key: key.public_spend_key,
    }
}

// ── DTOs ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SetUsernameRequest {
    /// Desired username (3-32 chars, lowercase `[a-z0-9_]`, no leading/trailing
    /// underscore). Submitted values are lowercased before validation.
    pub username: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SetUsernameResponse {
    /// The username as stored (lowercased).
    pub username: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MyUsernameResponse {
    /// The caller's username, or `null` if they have not claimed one.
    pub username: Option<String>,
}

/// A user's per-asset receiving public keys, by asset.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PublicKeysInfo {
    pub btc: Option<String>,
    pub ltc: Option<String>,
    pub xmr: Option<String>,
    pub wow: Option<String>,
    pub grin: Option<String>,
}

/// Result of resolving a username. Constant-shape: the same fields are always
/// present, so the response is not a structure oracle.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LookupUsernameResponse {
    /// Whether a user owns this username.
    pub registered: bool,
    /// The resolved user id (UUID string), if registered.
    pub user_id: Option<String>,
    /// The canonical (lowercased) username, if registered.
    pub username: Option<String>,
    /// The user's per-asset receiving public keys, if registered.
    pub public_keys: Option<PublicKeysInfo>,
}

/// Register or update one of the caller's per-asset public keys.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RegisterKeyRequest {
    /// Asset the key is for (`btc`, `ltc`, `xmr`, `wow`, `grin`).
    pub asset: String,
    /// The public key (format depends on the asset).
    pub public_key: String,
    /// XMR/WOW only: the public spend key.
    pub public_spend_key: Option<String>,
}

/// A single per-asset public key.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserKeyInfo {
    /// Asset the key is for (lowercase: `btc`, `ltc`, `xmr`, `wow`, `grin`).
    pub asset: String,
    pub public_key: String,
    /// XMR/WOW only: the public spend key.
    pub public_spend_key: Option<String>,
}

/// A user's full set of per-asset public keys.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserKeysResponse {
    pub keys: Vec<UserKeyInfo>,
}

// ── POST /users/me/username ───────────────────────────────────────────────────

/// Claim or update the authenticated user's username.
///
/// The submitted value is lowercased, validated, and checked against the
/// reserved list before the DB write. The UNIQUE constraint is the atomic claim:
/// a collision (taken or reserved) is a 409, never a 500.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/users/me/username",
    request_body = SetUsernameRequest,
    responses(
        (status = 200, description = "Username claimed or updated", body = SetUsernameResponse),
        (status = 401, description = "Missing or invalid token"),
        (status = 409, description = "Username is taken or reserved")
    ),
    tag = "users"
)]
#[instrument(skip(state, headers, req))]
pub async fn set_username(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetUsernameRequest>,
) -> Result<Json<SetUsernameResponse>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;

    let username = req.username.to_lowercase();
    validate_username(&username)?;

    // The UNIQUE constraint is the atomic claim; a collision surfaces as 409
    // CONFLICT (not 500) via `set_username`/`update_username`.
    state.db.set_username(user_id, &username).await?;

    // `user_id` is an opaque UUID (safe to log); the username itself is omitted.
    info!(user_id = %user_id, username_len = username.len(), "username set");

    Ok(Json(SetUsernameResponse { username }))
}

// ── GET /users/me/username ────────────────────────────────────────────────────

/// The authenticated user's own username (or `null`).
#[utoipa::path(
    security(("bearer_auth" = [])),
    get,
    path = "/users/me/username",
    responses(
        (status = 200, description = "Caller's username", body = MyUsernameResponse),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "users"
)]
#[instrument(skip(state, headers))]
pub async fn get_my_username(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<MyUsernameResponse>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    let user = state
        .db
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| AppError::AuthError("Invalid or expired token".into()))?;
    Ok(Json(MyUsernameResponse {
        username: user.username,
    }))
}

// ── GET /users/by-username/:username ──────────────────────────────────────────

/// Resolve a username to its user and that user's receiving public keys.
///
/// Public: this is how a sender discovers where to send. The lookup is
/// case-insensitive (the handle is canonicalized lowercase). An unknown handle
/// returns the same constant-shape response with `registered: false`.
#[utoipa::path(
    get,
    path = "/users/by-username/{username}",
    params(("username" = String, Path, description = "Username to resolve")),
    responses((status = 200, description = "Username resolution result", body = LookupUsernameResponse)),
    tag = "users"
)]
#[instrument(skip(state))]
pub async fn lookup_username(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Json<LookupUsernameResponse>, AppError> {
    let username = username.to_lowercase();

    let Some(user) = state.db.get_user_by_username(&username).await? else {
        return Ok(Json(LookupUsernameResponse {
            registered: false,
            user_id: None,
            username: None,
            public_keys: None,
        }));
    };

    let keys = state.db.get_user_keys(user.id).await?;
    // Pick by key_type, not "first row of this asset". Grin has two rows, so an
    // unqualified `find` returns whichever the query happened to yield.
    let key_for = |asset: AssetType| {
        let pick = |key_type: &str| {
            keys.iter()
                .find(|k| k.asset == asset && k.key_type == key_type)
                .map(|k| k.public_key.clone())
        };
        match asset {
            // Senders need the payable slatepack address. The `primary` row holds
            // the key that signs, which is a different derivation and not payable,
            // so fall back to it only when it still carries a pre-split address.
            AssetType::Grin => pick(KEY_TYPE_SLATEPACK)
                .or_else(|| pick(KEY_TYPE_PRIMARY).filter(|v| is_grin_slatepack_address(v))),
            _ => pick(KEY_TYPE_PRIMARY),
        }
    };
    let public_keys = PublicKeysInfo {
        btc: key_for(AssetType::Btc),
        ltc: key_for(AssetType::Ltc),
        xmr: key_for(AssetType::Xmr),
        wow: key_for(AssetType::Wow),
        grin: key_for(AssetType::Grin),
    };

    Ok(Json(LookupUsernameResponse {
        registered: true,
        user_id: Some(user.id.to_string()),
        username: user.username,
        public_keys: Some(public_keys),
    }))
}

// ── key_type selection ─────────────────────────────────────────

/// The key a signature is verified against, and the default for every asset.
pub const KEY_TYPE_PRIMARY: &str = "primary";

/// A Grin wallet's canonical slatepack address: a payable address, NOT the key
/// that signs. Kept in its own row so it cannot displace [`KEY_TYPE_PRIMARY`].
pub const KEY_TYPE_SLATEPACK: &str = "slatepack";

/// Is this a bech32 Grin slatepack address rather than a raw public key?
///
/// The two Grin values a wallet registers are distinguishable by construction: a
/// slatepack address is bech32 under the `grin`/`tgrin` HRP, and a hex public key
/// cannot begin with those characters because `g`, `r`, `i` and `n` are not hex
/// digits. So this is a total discriminator, not a heuristic that a well-formed
/// public key could trip.
pub(crate) fn is_grin_slatepack_address(value: &str) -> bool {
    let v = value.trim();
    v.starts_with("grin1") || v.starts_with("tgrin1")
}

/// Which row a registered key belongs in.
///
/// A Grin wallet publishes two different keys derived two different ways: the
/// Smirk-derived public key that website sign-in verifies, and the canonical
/// grin-wallet slatepack address that senders pay. Routing them by value keeps
/// the second from overwriting the first on `(user_id, asset, key_type)`, and it
/// does so for wallets that are ALREADY SHIPPED, which cannot be taught to send a
/// `key_type` of their own.
pub(crate) fn key_type_for(asset: AssetType, public_key: &str) -> &'static str {
    match asset {
        AssetType::Grin if is_grin_slatepack_address(public_key) => KEY_TYPE_SLATEPACK,
        _ => KEY_TYPE_PRIMARY,
    }
}

// ── POST /keys ────────────────────────────────────────────────────────────────

/// Register or update one of the authenticated user's per-asset public keys.
///
/// Idempotent: the DB upsert keys on `(user_id, asset, key_type)`, so re-posting
/// the same asset replaces the stored key material in place.
#[utoipa::path(
    security(("bearer_auth" = [])),
    post,
    path = "/keys",
    request_body = RegisterKeyRequest,
    responses(
        (status = 200, description = "Key registered or updated", body = UserKeyInfo),
        (status = 400, description = "Invalid asset"),
        (status = 401, description = "Missing or invalid token")
    ),
    tag = "users"
)]
#[instrument(skip(state, headers, req))]
pub async fn register_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterKeyRequest>,
) -> Result<Json<UserKeyInfo>, AppError> {
    let user_id = extract_user_id_from_token(&state, &headers).await?;
    let asset = parse_asset(&req.asset)?;
    let key_type = key_type_for(asset, &req.public_key);

    let key = state
        .db
        .upsert_user_key(NewUserKey {
            user_id,
            asset,
            public_key: req.public_key.clone(),
            public_spend_key: req.public_spend_key.clone(),
            key_type: key_type.to_string(),
        })
        .await?;

    info!(user_id = %user_id, asset = %asset, key_type, "registered public key");
    Ok(Json(key_info(key)))
}

// ── GET /users/:user_id/keys ──────────────────────────────────────────────────

/// List a user's per-asset receiving public keys.
///
/// Public: a sender fetches these to construct a payment to `user_id`.
#[utoipa::path(
    get,
    path = "/users/{user_id}/keys",
    params(("user_id" = String, Path, description = "User id (UUID)")),
    responses(
        (status = 200, description = "The user's public keys", body = UserKeysResponse),
        (status = 400, description = "Malformed user id")
    ),
    tag = "users"
)]
#[instrument(skip(state))]
pub async fn get_user_keys(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserKeysResponse>, AppError> {
    let keys = state.db.get_user_keys(user_id).await?;
    Ok(Json(UserKeysResponse {
        keys: keys.into_iter().map(key_info).collect(),
    }))
}

// ── GET /users/:user_id/keys/:asset ───────────────────────────────────────────

/// Fetch a user's receiving public key for one asset.
#[utoipa::path(
    get,
    path = "/users/{user_id}/keys/{asset}",
    params(
        ("user_id" = String, Path, description = "User id (UUID)"),
        ("asset" = String, Path, description = "Asset (btc, ltc, xmr, wow, grin)")
    ),
    responses(
        (status = 200, description = "The user's key for this asset", body = UserKeyInfo),
        (status = 400, description = "Invalid asset"),
        (status = 404, description = "User has no key for this asset")
    ),
    tag = "users"
)]
#[instrument(skip(state))]
pub async fn get_user_key_for_asset(
    State(state): State<Arc<AppState>>,
    Path((user_id, asset)): Path<(Uuid, String)>,
) -> Result<Json<UserKeyInfo>, AppError> {
    let asset = parse_asset(&asset)?;
    let key = state
        .db
        .get_user_key(user_id, asset)
        .await?
        .ok_or_else(|| AppError::NotFound("User has no key for this asset".into()))?;
    Ok(Json(key_info(key)))
}

// ── router ────────────────────────────────────────────────────────────────────

/// User routes, RELATIVE to the `/api/v1` mount point. The application is
/// expected to `Router::new().nest("/api/v1", users::routes())`.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/users/me/username",
            post(set_username).get(get_my_username),
        )
        .route("/users/by-username/:username", get(lookup_username))
        .route("/keys", post(register_key))
        .route("/users/:user_id/keys", get(get_user_keys))
        .route("/users/:user_id/keys/:asset", get(get_user_key_for_asset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_rules() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("a_b_2").is_ok());
        assert!(validate_username("ab").is_err()); // too short
        assert!(validate_username("_alice").is_err()); // leading underscore
        assert!(validate_username("alice_").is_err()); // trailing underscore
        assert!(validate_username("al ice").is_err()); // space
    }

    #[test]
    fn reserved_usernames_are_conflicts() {
        match validate_username("admin") {
            Err(AppError::Conflict(_)) => {}
            other => panic!("expected Conflict for reserved name, got {other:?}"),
        }
        match validate_username("smirk") {
            Err(AppError::Conflict(_)) => {}
            other => panic!("expected Conflict for reserved name, got {other:?}"),
        }
        // A non-reserved, well-formed name passes.
        assert!(validate_username("alice123").is_ok());
    }

    /// The two Grin values a wallet registers must land in different rows, or
    /// the second overwrites the first and Grin sign-in stops resolving.
    #[test]
    fn grin_signing_key_and_slatepack_address_get_separate_rows() {
        // A 64-hex public key is the thing a signature is checked against.
        let hex_key = "b".repeat(64);
        assert_eq!(key_type_for(AssetType::Grin, &hex_key), KEY_TYPE_PRIMARY);

        // A bech32 slatepack address is payable, not signable, so it is kept apart.
        let addr = "grin1qqv9hlxpazdvs0zt6f2qm2r9j8sjkz5t2e2y8y4dm2xu9zr9s6zjqk5ldrz";
        assert_eq!(key_type_for(AssetType::Grin, addr), KEY_TYPE_SLATEPACK);
        assert_ne!(
            key_type_for(AssetType::Grin, addr),
            key_type_for(AssetType::Grin, &hex_key)
        );
    }

    /// The split is Grin-only: no other asset grows a second row, whatever it
    /// registers.
    #[test]
    fn other_assets_are_unaffected_by_the_grin_split() {
        for asset in [
            AssetType::Btc,
            AssetType::Ltc,
            AssetType::Xmr,
            AssetType::Wow,
        ] {
            assert_eq!(key_type_for(asset, &"a".repeat(64)), KEY_TYPE_PRIMARY);
            // Even a value shaped like a slatepack address stays primary.
            assert_eq!(
                key_type_for(asset, "grin1qqv9hlxpazdvs0zt"),
                KEY_TYPE_PRIMARY
            );
        }
    }

    /// The discriminator has to be total, not a guess: a hex public key cannot
    /// begin with the Grin HRP, because those letters are not hex digits.
    #[test]
    fn slatepack_discriminator_separates_addresses_from_public_keys() {
        assert!(is_grin_slatepack_address("grin1qqv9hlxpazdvs0zt"));
        assert!(is_grin_slatepack_address("tgrin1qqv9hlxpazdvs0zt"));
        assert!(is_grin_slatepack_address("  grin1qqv9hlxpazdvs0zt  "));

        for c in "0123456789abcdefABCDEF".chars() {
            let key: String = std::iter::repeat(c).take(64).collect();
            assert!(
                !is_grin_slatepack_address(&key),
                "hex public key of {c:?} must not read as an address"
            );
        }
        assert!(!is_grin_slatepack_address(""));
    }

    #[test]
    fn asset_parse_roundtrips_and_rejects() {
        assert_eq!(parse_asset("BTC").unwrap(), AssetType::Btc);
        assert_eq!(parse_asset("grin").unwrap(), AssetType::Grin);
        assert!(parse_asset("doge").is_err());
    }

    /// Wire-shape: the key registration request accepts a snake_case asset
    /// string and an optional spend key.
    #[test]
    fn register_key_request_wire_shape() {
        let json = r#"{"asset":"xmr","public_key":"abcd","public_spend_key":"ef01"}"#;
        let req: RegisterKeyRequest = serde_json::from_str(json).expect("deserializes");
        assert_eq!(req.asset, "xmr");
        assert_eq!(req.public_spend_key.as_deref(), Some("ef01"));

        let minimal = r#"{"asset":"btc","public_key":"deadbeef"}"#;
        let req: RegisterKeyRequest = serde_json::from_str(minimal).expect("deserializes");
        assert!(req.public_spend_key.is_none());
    }
}
