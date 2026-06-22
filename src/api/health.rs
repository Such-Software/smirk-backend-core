//! Health / liveness endpoint.

use axum::Json;
use serde::Serialize;

/// Liveness response.
#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    /// Always `"ok"` when the service is reachable.
    pub status: String,
}

/// Liveness probe.
///
/// Returns `200` with `{ "status": "ok" }` whenever the server is up. Used by
/// load balancers and uptime checks; requires no authentication.
#[utoipa::path(
    get,
    path = "/health",
    responses((status = 200, description = "Service is up", body = HealthResponse)),
    tag = "system"
)]
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}
