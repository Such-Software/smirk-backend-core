//! L1 integration: the dark `FEATURE_XMR_SUBADDR_PROVISIONING` gate.
//!
//! Deterministic, no-network paths only: whether the route is mounted, and
//! whether `/capabilities` advertises the same answer the router enforces. The
//! networked happy path (a real LWS confirming a subaddress range) needs a live
//! gate and lives in the separate gitignored L3 harness.
//!
//! The flag is a process-wide environment variable, so these tests live in their
//! own binary (env is per-process) and take a lock around every set/restore.

mod common;

use axum::http::StatusCode;
use serde_json::json;

const FLAG: &str = "FEATURE_XMR_SUBADDR_PROVISIONING";
const ROUTE: &str = "/api/v1/wallet/lws/provision_subaddrs";

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set the flag, run `body`, then restore the previous value. Held across the
/// whole test because `build_router` reads the flag when it mounts routes.
struct FlagGuard {
    prev: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl FlagGuard {
    fn set(value: Option<&str>) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var(FLAG).ok();
        match value {
            Some(v) => std::env::set_var(FLAG, v),
            None => std::env::remove_var(FLAG),
        }
        Self { prev, _lock: lock }
    }
}

impl Drop for FlagGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(v) => std::env::set_var(FLAG, v),
            None => std::env::remove_var(FLAG),
        }
    }
}

#[tokio::test]
async fn provision_route_is_absent_while_the_flag_is_off() {
    let _flag = FlagGuard::set(None);
    let app = require_app!();
    let (_uid, access, _r) = app.mint_session().await;

    // Not mounted at all: an authenticated, well-formed request still 404s, so a
    // client cannot reach the feature by guessing the path.
    let (status, _) = app
        .request(
            "POST",
            ROUTE,
            Some(&access),
            Some(json!({ "asset": "xmr", "address": "4Addr", "view_key": "00" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // And the capability says so, so a client never has to probe.
    let (status, body) = app.request("GET", "/api/v1/capabilities", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["features"]["xmr_subaddr_provisioning"], json!(false));
}

#[tokio::test]
async fn provision_route_is_mounted_and_validates_while_the_flag_is_on() {
    let _flag = FlagGuard::set(Some("1"));
    let app = require_app!();

    // Mounted: an unauthenticated request is rejected by the JWT gate (401),
    // NOT by the router (404), which is what proves the route exists.
    let (status, _) = app
        .request(
            "POST",
            ROUTE,
            None,
            Some(json!({ "asset": "xmr", "address": "4Addr", "view_key": "00" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (_uid, access, _r) = app.mint_session().await;

    // Authed but an unknown asset -> 400, still resolved before any LWS call.
    let (status, body) = app
        .request(
            "POST",
            ROUTE,
            Some(&access),
            Some(json!({ "asset": "doge", "address": "x", "view_key": "00" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");

    // A malformed view key is rejected before any LWS call too.
    let (status, body) = app
        .request(
            "POST",
            ROUTE,
            Some(&access),
            Some(json!({
                "asset": "xmr",
                "address": "4SomeAddress",
                "view_key": "tooshort",
                "max_minor": 31
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn flag_parsing_agrees_between_the_router_and_capabilities() {
    // Every accepted spelling must mount the route AND be advertised, so a
    // client can negotiate instead of blindly calling a route that 404s.
    for spelling in ["1", "true", "TRUE", "On", " yes "] {
        let _flag = FlagGuard::set(Some(spelling));
        let app = require_app!();
        let (_uid, access, _r) = app.mint_session().await;

        let (status, _) = app
            .request(
                "POST",
                ROUTE,
                Some(&access),
                Some(json!({ "asset": "doge", "address": "x", "view_key": "00" })),
            )
            .await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "{spelling:?} should mount the route"
        );

        let (_s, body) = app.request("GET", "/api/v1/capabilities", None, None).await;
        // Advertised only when a CryptoNote chain is actually serviceable; when
        // it is not, the route may exist but the capability must stay false
        // rather than promise a chain this instance cannot serve.
        let advertised = body["features"]["xmr_subaddr_provisioning"] == json!(true);
        let xmr_or_wow = body["chains"]["xmr"]["enabled"] == json!(true)
            || body["chains"]["wow"]["enabled"] == json!(true);
        assert_eq!(advertised, xmr_or_wow, "{spelling:?}");
    }

    for spelling in ["0", "false", "off", "no", "", "maybe"] {
        let _flag = FlagGuard::set(Some(spelling));
        let app = require_app!();
        let (_uid, access, _r) = app.mint_session().await;

        let (status, _) = app
            .request(
                "POST",
                ROUTE,
                Some(&access),
                Some(json!({ "asset": "xmr", "address": "4Addr", "view_key": "00" })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{spelling:?} must leave the feature dark"
        );

        let (_s, body) = app.request("GET", "/api/v1/capabilities", None, None).await;
        assert_eq!(
            body["features"]["xmr_subaddr_provisioning"],
            json!(false),
            "{spelling:?}"
        );
    }
}
