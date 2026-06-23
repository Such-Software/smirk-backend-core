//! L1 integration: Grin (view-only) wallet endpoints through the real router.
//!
//! Deterministic, no-network paths: the JWT gate and rewind_hash validation,
//! resolved before any grin-wallet call. The networked happy paths live in the
//! separate gitignored L3 harness.

mod common;

use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn scan_requires_a_token() {
    let app = require_app!();
    let (status, _) = app
        .request(
            "POST",
            "/api/v1/wallet/grin/scan",
            None,
            Some(json!({ "rewind_hash": "00" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn scan_rejects_malformed_rewind_hash() {
    let app = require_app!();
    let (_uid, access, _r) = app.mint_session().await;
    // Authed, but the rewind_hash is not 64 hex -> 400 before any grin call.
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/wallet/grin/scan",
            Some(&access),
            Some(json!({ "rewind_hash": "tooshort" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn height_requires_a_token() {
    let app = require_app!();
    let (status, _) = app
        .request("GET", "/api/v1/wallet/grin/height", None, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn broadcast_requires_a_token() {
    let app = require_app!();
    let (status, _) = app
        .request(
            "POST",
            "/api/v1/wallet/grin/broadcast",
            None,
            Some(json!({ "tx": {} })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
