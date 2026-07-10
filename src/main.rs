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
    // Payment processor for the pay-to-register gate (None unless it's enabled).
    let payment = smirk_backend_core::infra::payment::from_config(&config)?;
    // Optional Nostr relay (messaging plane); None unless RELAY_ENABLED.
    let relay = smirk_backend_core::infra::relay::from_config(&config)?;

    // First-run bootstrap latch (operator §3.2). Only meaningful with the admin
    // surface enabled. Fail closed on a tampered latch (restore-to-pre-bootstrap).
    if config.admin.enabled {
        use smirk_backend_core::infra::db::SetupState;
        let secret = &config.admin.key_integrity_secret;
        match db.read_setup_state(secret).await? {
            SetupState::Fresh => {
                // Adopt an existing deployment as already-bootstrapped (so a live
                // upgrade never exposes a setup window); a truly empty DB begins
                // uninitialized, awaiting `smirk-admin setup`. Adopt on EITHER
                // wallet users OR admin keys, so deleting the latch row on a
                // CLI-bootstrapped-but-no-users instance re-latches Locked rather
                // than silently downgrading to uninitialized.
                let adopt = db.has_any_users().await? || db.has_any_admin_keys().await?;
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
        payment,
        relay,
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

    // Background erasure execution: confirmed requests past their grace window
    // are deleted (per-table policy + cascade + hash-chained audit, one tx each).
    if state.config.retention.erasure_enabled {
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                match smirk_backend_core::api::erasure::run_erasure_sweep(&state, 50).await {
                    Ok(n) if n > 0 => tracing::info!(executed = n, "erasure sweep"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "erasure sweep failed"),
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
        // Fail-closed bind guard: refuse a non-loopback admin bind unless the
        // operator explicitly opts in (confidentiality is by socket). Resolve the
        // address (so "localhost" works) and require EVERY resolved addr to be
        // loopback — a prefix check would accept "localhost.evil.com".
        use std::net::ToSocketAddrs;
        let is_loopback = match admin_addr.to_socket_addrs() {
            Ok(addrs) => {
                let addrs: Vec<_> = addrs.collect();
                !addrs.is_empty() && addrs.iter().all(|a| a.ip().is_loopback())
            }
            Err(_) => false,
        };
        if !is_loopback && !state.config.admin.allow_public_bind {
            return Err(format!(
                "ADMIN_BIND {admin_addr} is not loopback; set ADMIN_ALLOW_PUBLIC_BIND=true to override \
                 (and front it with Tor client-auth / a trusted proxy)"
            )
            .into());
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

    // Nostr relay event-admission (nauthz) gRPC service — only for a non-`open`
    // write policy (open needs no admission). Loopback socket, like the admin
    // plane; nostr-rs-relay is configured to call it per inbound event.
    if let Some(relay) = state.relay.clone() {
        use smirk_backend_core::infra::relay::WritePolicy;
        if relay.write_policy() != WritePolicy::Open {
            let addr: std::net::SocketAddr = state
                .config
                .messaging
                .relay
                .admission_bind
                .parse()
                .map_err(|e| format!("invalid RELAY_ADMISSION_BIND: {e}"))?;
            let db = state.db.clone();
            tracing::info!("relay event-admission (nauthz) listening on {addr}");
            tokio::spawn(async move {
                let result = smirk_backend_core::infra::relay::nauthz::serve(addr, relay, db).await;
                // nostr-rs-relay fails OPEN if the admission service is unreachable
                // (accepts every event). So a dead admission = an unrestricted
                // relay. Fail SAFE: take the backend down so the operator's
                // supervisor restarts a clean relay+admission pair, rather than
                // leaving an open relay running behind a healthy-looking API.
                tracing::error!(
                    ?result,
                    "relay admission service stopped — exiting to avoid an unrestricted relay"
                );
                std::process::exit(1);
            });
        }
    }

    // Public-tips "money-in" worker: one funding pass per 60s (confirmation
    // counting for XMR/WOW, then the amount verifier across all
    // pending_confirmation tips). Only runs when tips are enabled. A panic in a
    // single pass is caught + backed off so the loop survives (visible in logs)
    // rather than silently dying and stranding every pending tip.
    if state.config.features.tips {
        use futures::FutureExt;
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                let cycle = std::panic::AssertUnwindSafe(
                    smirk_backend_core::tips::run_tip_confirmation_cycle(state.clone()),
                );
                if cycle.catch_unwind().await.is_err() {
                    tracing::error!("tip confirmation cycle panicked; continuing after backoff");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        });
    }

    // Public-tips "money-out" reconciler: the settle-on-sweep-confirmation pass
    // (probe each claiming tip's ADDRESS, settle claiming -> claimed once the
    // sweep confirms to the per-asset depth). Sole new writer of 'claimed'. Runs
    // an immediate startup pass (so a restart doesn't wait a full interval before
    // settling anything that confirmed while we were down) then every 60s. Same
    // catch_unwind guard as the money-in worker.
    if state.config.features.tips {
        use futures::FutureExt;
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                let cycle = std::panic::AssertUnwindSafe(
                    smirk_backend_core::tips::run_sweep_reconcile_cycle(state.clone()),
                );
                if cycle.catch_unwind().await.is_err() {
                    tracing::error!("sweep reconcile cycle panicked; continuing after backoff");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        });
    }

    // Public-tips reorg-check pass: re-probe settled tips and revert any whose
    // recorded sweep was orphaned by a chain reorg. Lowest-frequency, novel, and
    // recoverable, so it runs on a slower cadence (300s) than the confirm pass.
    if state.config.features.tips {
        use futures::FutureExt;
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                tick.tick().await;
                let cycle = std::panic::AssertUnwindSafe(
                    smirk_backend_core::tips::run_sweep_reorg_cycle(state.clone()),
                );
                if cycle.catch_unwind().await.is_err() {
                    tracing::error!("sweep reorg cycle panicked; continuing after backoff");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        });
    }

    // Public-tips draft GC: hourly, cancel `draft` rows abandoned mid-flow (> 7
    // days, never funded-attached) and warn per cancelled row. Same catch_unwind
    // guard as the money-in/out workers.
    if state.config.features.tips {
        use futures::FutureExt;
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let cycle = std::panic::AssertUnwindSafe(
                    smirk_backend_core::tips::run_tip_draft_gc_cycle(state.clone()),
                );
                if cycle.catch_unwind().await.is_err() {
                    tracing::error!("tip draft GC cycle panicked; continuing after backoff");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        });
    }

    // Public-tips lifecycle GC: every 5 min, cancel stuck `pending_confirmation`
    // rows (> 7 days) and warn-only-scan stuck `claiming` rows (> 15 min). Same
    // catch_unwind guard.
    if state.config.features.tips {
        use futures::FutureExt;
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                tick.tick().await;
                let cycle = std::panic::AssertUnwindSafe(
                    smirk_backend_core::tips::run_tip_lifecycle_gc_cycle(state.clone()),
                );
                if cycle.catch_unwind().await.is_err() {
                    tracing::error!("tip lifecycle GC cycle panicked; continuing after backoff");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
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
