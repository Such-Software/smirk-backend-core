//! OpenAPI specification assembly.
//!
//! `ApiDoc` aggregates the annotated handlers into the spec that is the single
//! source of truth for the API contract and the wallet's generated TypeScript
//! client. Add a path here once its handler carries `#[utoipa::path(...)]` and
//! its request/response types derive `utoipa::ToSchema`.

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "smirk-backend-core",
        version = "0.3.0",
        description = "Open, self-hostable backend for the Smirk non-custodial multi-chain wallet."
    ),
    paths(
        crate::api::health::health,
        crate::api::auth::pow_challenge,
        crate::api::auth::extension_register,
        crate::api::auth::check_restore,
        crate::api::auth::refresh_token,
        crate::api::auth::logout,
        crate::api::auth::get_me,
        crate::api::auth::nostr_login,
        crate::api::auth::nostr_link,
        crate::api::website::website_challenge,
        crate::api::website::website_verify,
        crate::api::users::set_username,
        crate::api::users::get_my_username,
        crate::api::users::lookup_username,
        crate::api::users::register_key,
        crate::api::users::get_user_keys,
        crate::api::users::get_user_key_for_asset,
        crate::api::nip05::well_known_nostr,
    ),
    components(schemas(
        crate::api::health::HealthResponse,
        crate::api::auth::AuthResponse,
        crate::api::auth::UserInfo,
        crate::api::auth::AssetPublicKey,
        crate::api::auth::ExtensionRegisterRequest,
        crate::api::auth::CheckRestoreRequest,
        crate::api::auth::CheckRestoreResponse,
        crate::api::auth::RefreshTokenRequest,
        crate::api::auth::LogoutRequest,
        crate::api::auth::LogoutResponse,
        crate::api::auth::NostrLinkRequest,
        crate::api::auth::NostrLinkResponse,
        crate::api::website::WebsiteChallengeRequest,
        crate::api::website::WebsiteChallengeResponse,
        crate::api::website::AssetSignature,
        crate::api::website::WebsiteVerifyRequest,
        crate::api::users::SetUsernameRequest,
        crate::api::users::SetUsernameResponse,
        crate::api::users::MyUsernameResponse,
        crate::api::users::PublicKeysInfo,
        crate::api::users::LookupUsernameResponse,
        crate::api::users::RegisterKeyRequest,
        crate::api::users::UserKeyInfo,
        crate::api::users::UserKeysResponse,
        crate::api::nip05::WellKnownResponse,
    )),
    tags(
        (name = "system", description = "Service health and metadata."),
        (name = "auth", description = "Wallet authentication: registration, restore, refresh, sessions, Nostr identity.")
    )
)]
pub struct ApiDoc;
