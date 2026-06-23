//! smirk-backend-core server entry point.
//!
//! Loads and validates configuration (fail-closed), connects the database and
//! runs migrations, builds the shared [`AppState`], and serves the HTTP API.
//! Routes are added as handler modules land; for now it serves health.

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;

use smirk_backend_core::{
    build_router, config::Config, core::session::SessionManager, infra::chains::ChainClients,
    infra::db::Database, AppState,
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
    let chains = ChainClients::from_config(&config)?;

    let addr = format!("{}:{}", config.server_host, config.server_port);
    let state = Arc::new(AppState {
        config,
        db,
        sessions,
        chains,
        web_challenges: Arc::default(),
    });

    // Periodic GC of expired website-auth challenges. Bounds the single-node
    // in-memory store so the unauthenticated challenge endpoint cannot grow it
    // without limit. (The fleet path moves this state to a shared store.)
    {
        let challenges = state.web_challenges.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(120));
            loop {
                tick.tick().await;
                challenges.write().await.retain(|_, c| !c.is_expired());
            }
        });
    }

    // Periodic expiry of stale Grin relay slatepacks (only when the relay is
    // enabled). The respond/finalize paths already reject expired relays in their
    // UPDATE guard; this sweep flips past-TTL rows to Expired so the table stays
    // bounded and the lifecycle reflects reality.
    if state.config.features.grin_relay {
        let db = state.db.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                if let Err(e) = db.expire_old_slatepacks().await {
                    tracing::warn!(error = %e, "grin slatepack expiry sweep failed");
                }
            }
        });
    }

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("smirk-backend-core listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
