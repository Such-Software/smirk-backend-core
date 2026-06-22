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
    )),
    tags(
        (name = "system", description = "Service health and metadata."),
        (name = "auth", description = "Wallet authentication: registration, restore, refresh, sessions, Nostr identity.")
    )
)]
pub struct ApiDoc;
