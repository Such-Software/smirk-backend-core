//! smirk-backend-core server entry point.
//!
//! Loads and validates configuration (fail-closed), connects the database and
//! runs migrations, builds the shared [`AppState`], and serves the HTTP API.
//! Routes are added as handler modules land; for now it serves health.

use std::sync::Arc;

use axum::{routing::get, Router};
use sqlx::postgres::PgPoolOptions;

use smirk_backend_core::{
    api::health, config::Config, core::session::SessionManager, infra::db::Database, AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let _ = dotenvy::dotenv();

    // Fail-closed: aborts on a weak/missing/inconsistent secret.
    let config = Config::from_env()?;
    tracing::info!(environment = %config.environment, "configuration loaded");

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let db = Database::new(
        pool,
        config.secrets.seed_fingerprint_pepper.clone(),
        config.secrets.ip_salt.clone(),
    );
    let sessions = SessionManager::new(&config.auth.jwt_secret, config.auth.jwt_expiry_hours);

    let addr = format!("{}:{}", config.server_host, config.server_port);
    let state = Arc::new(AppState {
        config,
        db,
        sessions,
        web_challenges: Arc::default(),
    });

    let app = Router::new()
        .route("/health", get(health::health))
        .nest("/api/v1", smirk_backend_core::api::auth::routes())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("smirk-backend-core listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
