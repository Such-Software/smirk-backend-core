//! Integration-test harness (L1: access + read, fundless).
//!
//! Spins the real router + `AppState` against a Postgres database named by
//! `TEST_DATABASE_URL`. When that is unset the helpers return `None` and tests
//! self-skip, so `cargo test` stays green without a database; CI provides one.
//!
//! It uses only deterministic, non-sensitive TEST secrets and ephemeral
//! generated identities — never a funded or otherwise sensitive wallet seed.
//! (Funded, two-party L3+ scenarios live in a separate, gitignored harness.)

#![allow(dead_code)] // helpers are shared across several test binaries

use std::sync::{Arc, Once};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

use smirk_backend_core::{
    build_router, config::Config, core::session::SessionManager, infra::chains::ChainClients,
    infra::db::Database, AppState,
};

static INIT_ENV: Once = Once::new();

/// Set deterministic, non-sensitive test secrets once, so the real (validated)
/// `Config::from_env` path can build a test config. These are not credentials.
fn init_test_env(database_url: &str) {
    INIT_ENV.call_once(|| {
        std::env::set_var("DATABASE_URL", database_url);
        std::env::set_var("ENVIRONMENT", "development");
        std::env::set_var("JWT_SECRET", "integration-test-jwt-secret-0123456789ab");
        std::env::set_var(
            "SEED_FINGERPRINT_PEPPER",
            "integration-test-seed-pepper-0123456789ab",
        );
        std::env::set_var(
            "REFRESH_TOKEN_PEPPER",
            "integration-test-refresh-pepper-0123456789ab",
        );
        std::env::set_var("IP_SALT", "integration-test-ip-salt-0123456789");
        std::env::set_var("PUBLIC_API_URL", "http://localhost:8080/api/v1");
    });
}

/// The router + state under test, or `None` if no `TEST_DATABASE_URL` is set.
pub async fn try_app() -> Option<TestApp> {
    let url = std::env::var("TEST_DATABASE_URL").ok()?;
    init_test_env(&url);
    let config = Config::from_env().expect("valid test config");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
        .expect("connect test database");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");

    let db = Database::new(
        pool,
        config.secrets.seed_fingerprint_pepper.clone(),
        config.secrets.ip_salt.clone(),
    );
    let sessions = SessionManager::new(&config.auth.jwt_secret, config.auth.jwt_expiry_hours);
    let chains = ChainClients::from_config(&config).expect("build chain clients");
    let state = Arc::new(AppState {
        config,
        db,
        sessions,
        chains,
        web_challenges: Arc::default(),
    });

    Some(TestApp {
        router: build_router(state.clone()),
        state,
    })
}

/// Skip the current test (printing why) when no test DB is configured.
#[macro_export]
macro_rules! require_app {
    () => {{
        match $crate::common::try_app().await {
            Some(app) => app,
            None => {
                eprintln!("skipping: TEST_DATABASE_URL not set");
                return;
            }
        }
    }};
}

pub struct TestApp {
    pub router: Router,
    pub state: Arc<AppState>,
}

impl TestApp {
    /// Issue a JSON request and return `(status, parsed-body-or-Null)`.
    pub async fn request(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        // The per-IP rate limiter keys on ConnectInfo; in production `main`
        // supplies it via into_make_service_with_connect_info. oneshot requests
        // don't, so inject a loopback peer (each test builds a fresh router with
        // fresh limiter state, so this never trips across tests).
        let mut builder =
            Request::builder()
                .method(method)
                .uri(uri)
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    0,
                ))));
        if let Some(t) = token {
            builder = builder.header("authorization", format!("Bearer {t}"));
        }
        let req = match body {
            Some(b) => builder
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&b).unwrap()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, json)
    }

    /// Create a fresh user with a random identity. Returns the user id.
    pub async fn create_user(&self) -> Uuid {
        use smirk_backend_core::models::db::NewUser;
        let user = self
            .state
            .db
            .create_user(NewUser {
                username: None,
                pubkey_hash: Some(format!("pk-{}", Uuid::new_v4())),
                nostr_pubkey: None,
                wallet_birthday: None,
                seed_fingerprint: None,
                xmr_start_height: None,
                wow_start_height: None,
            })
            .await
            .expect("create user");
        user.id
    }

    /// Create a user + an active session, returning `(user_id, access, refresh)`.
    /// Bypasses the signed-registration handshake so session-gated routes can be
    /// exercised without forging a BIP-137 signature.
    pub async fn mint_session(&self) -> (Uuid, String, String) {
        use smirk_backend_core::core::session::{hash_refresh_token, Platform};
        use smirk_backend_core::models::db::NewSession;
        let user_id = self.create_user().await;
        let pair = self
            .state
            .sessions
            .create_token_pair(user_id, Platform::Web, Uuid::new_v4())
            .expect("mint token pair");
        let hash = hash_refresh_token(
            &pair.refresh_token,
            &self.state.config.secrets.refresh_token_pepper,
        );
        self.state
            .db
            .create_session(NewSession {
                user_id,
                refresh_token_hash: hash,
                platform: "web".to_string(),
                device_info: None,
                ip_address: None,
                expires_at: chrono::Utc::now() + chrono::Duration::days(30),
            })
            .await
            .expect("create session");
        (user_id, pair.access_token, pair.refresh_token)
    }
}
