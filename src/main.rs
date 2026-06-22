//! smirk-backend-core server entry point.
//!
//! Minimal server skeleton. Configuration, application state, the full router,
//! and background tasks are added as modules land; for now it serves the
//! health endpoint so the build, the OpenAPI contract, and deployment wiring
//! are exercised end to end.

use axum::{routing::get, Router};
use smirk_backend_core::api::health;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/health", get(health::health));

    let addr = "0.0.0.0:8080";
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind listener");
    tracing::info!("smirk-backend-core listening on http://{addr}");
    axum::serve(listener, app).await.expect("server error");
}
