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
    paths(crate::api::health::health),
    components(schemas(crate::api::health::HealthResponse)),
    tags((name = "system", description = "Service health and metadata."))
)]
pub struct ApiDoc;
