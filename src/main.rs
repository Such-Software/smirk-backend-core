//! smirk-backend-core server entry point.
//!
//! Loads and validates configuration (fail-closed), connects the database and
//! runs migrations, builds the shared [`AppState`], and serves the HTTP API.
//! Routes are added as handler modules land; for now it serves health.

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;

use smirk_backend_core::{
    admin_router, build_router, config::Config, core::admin_session::AdminSessionManager,
    core::session::SessionManager, infra::chains::ChainClients, infra::db::Database, infra::prices,
    infra::prices::PriceSnapshot, AppState,
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

    // First-run bootstrap latch (operator §3.2). Only meaningful with the admin
    // surface enabled. Fail closed on a tampered latch (restore-to-pre-bootstrap).
    if config.admin.enabled {
        use smirk_backend_core::infra::db::SetupState;
        let secret = &config.admin.key_integrity_secret;
        match db.read_setup_state(secret).await? {
            SetupState::Fresh => {
                // Adopt an existing deployment as already-bootstrapped (so a live
                // upgrade never exposes a setup window); a truly empty DB begins
                // uninitialized, awaiting `smirk-admin setup`.
                let adopt = db.has_any_users().await?;
                db.init_server_config(secret, adopt).await?;
                if adopt {
                    tracing::info!("existing deployment adopted: bootstrap latched (locked)");
                } else {
                    tracing::warn!(
                        "fresh install: no admin yet — run `smirk-admin setup --pubkey <hex>`"
                    );
                }
            }
            SetupState::Uninitialized => {
                tracing::warn!("not yet bootstrapped — run `smirk-admin setup --pubkey <hex>`")
            }
            SetupState::Locked => tracing::info!("bootstrap latch: locked"),
            SetupState::Tampered => {
                return Err(
                    "server_config bootstrap latch MAC invalid (tamper or restore-to-pre-bootstrap); \
                     run `smirk-admin reset-setup --i-understand` if this is intentional"
                        .into(),
                );
            }
        }
    }

    let addr = format!("{}:{}", config.server_host, config.server_port);
    let prices_cache = Arc::new(tokio::sync::RwLock::new(PriceSnapshot::empty(
        &config.features.prices_currency,
    )));
    let admin_sessions = config
        .admin
        .enabled
        .then(|| AdminSessionManager::new(&config.admin.jwt_secret));
    let state = Arc::new(AppState {
        config,
        db,
        sessions,
        chains,
        web_challenges: Arc::default(),
        prices: prices_cache,
        admin_sessions,
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

    // Periodic expiry sweep for the unified challenge store. The consume query
    // already ignores expired rows; this just bounds the table.
    {
        let db = state.db.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                tick.tick().await;
                if let Err(e) = db.delete_expired_challenges().await {
                    tracing::warn!(error = %e, "challenge expiry sweep failed");
                }
            }
        });
    }

    // Background price refresh (only when the feed is enabled). On each tick we
    // fetch the configured feeds and replace the snapshot; a failure logs and
    // keeps the last good values rather than blanking them. The first interval
    // tick fires immediately, so prices populate at startup.
    if state.config.features.prices {
        let f = &state.config.features;
        match prices::PriceClient::new(&f.prices_provider, &f.prices_currency, &f.prices_assets) {
            Ok(client) if !client.is_empty() => {
                let cache = state.prices.clone();
                let period = prices::refresh_interval(f.prices_interval_secs);
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(period);
                    loop {
                        tick.tick().await;
                        match client.fetch().await {
                            Ok(prices) => {
                                let mut snap = cache.write().await;
                                snap.prices = prices;
                                snap.updated_at = Some(chrono::Utc::now());
                            }
                            Err(e) => tracing::warn!(error = %e, "price refresh failed"),
                        }
                    }
                });
            }
            Ok(_) => tracing::info!("price feed enabled but no assets configured; serving none"),
            Err(e) => tracing::warn!(error = %e, "price client init failed; feed disabled"),
        }
    }

    // Admin plane: a SEPARATE loopback listener (confidentiality is by socket,
    // not middleware ordering). The fail-closed non-loopback bind guard and the
    // browser/Host hardening land with the admin-posture subsystem; for now bind
    // to the configured (loopback-default) address and warn if it isn't local.
    if state.config.admin.enabled {
        let admin_addr = state.config.admin.bind.clone();
        if !admin_addr.starts_with("127.") && !admin_addr.starts_with("[::1]") {
            tracing::warn!(
                bind = %admin_addr,
                "admin plane is not bound to loopback — ensure this is intentional"
            );
        }
        let admin_app = admin_router(state.clone());
        let admin_listener = tokio::net::TcpListener::bind(&admin_addr).await?;
        tracing::info!("admin plane listening on http://{admin_addr}");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(
                admin_listener,
                admin_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            {
                tracing::error!(error = %e, "admin plane server exited");
            }
        });
    }

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("smirk-backend-core listening on http://{addr}");
    // ConnectInfo carries the peer IP that the per-IP rate limiter keys on.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
