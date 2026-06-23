//! L1 integration: Monero/Wownero wallet endpoints through the real router.
//!
//! Deterministic, no-network paths only: the JWT gate, asset validation, and
//! view-key / tx-hex / txid validation — all resolved before any LWS call. The
//! funded/networked happy paths live in the separate gitignored L3 harness.

mod common;

use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn balance_requires_a_token() {
    let app = require_app!();
    let (status, _) = app
        .request(
            "POST",
            "/api/v1/wallet/lws/balance",
            None,
            Some(json!({ "asset": "xmr", "address": "4Addr", "view_key": "00" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn balance_rejects_unknown_asset() {
    let app = require_app!();
    let (_uid, access, _r) = app.mint_session().await;
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/wallet/lws/balance",
            Some(&access),
            Some(json!({ "asset": "doge", "address": "x", "view_key": "00" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn balance_rejects_malformed_view_key() {
    let app = require_app!();
    let (_uid, access, _r) = app.mint_session().await;
    // Authed + valid asset + address, but the view key is not 64 hex -> 400
    // before any LWS call.
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/wallet/lws/balance",
            Some(&access),
            Some(json!({ "asset": "xmr", "address": "4SomeAddress", "view_key": "tooshort" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn register_requires_a_token() {
    let app = require_app!();
    let (status, _) = app
        .request(
            "POST",
            "/api/v1/wallet/lws/register",
            None,
            Some(json!({ "asset": "xmr", "address": "4Addr", "view_key": "00" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn submit_rejects_malformed_tx_hex() {
    let app = require_app!();
    let (_uid, access, _r) = app.mint_session().await;
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/wallet/lws/submit_tx",
            Some(&access),
            Some(json!({ "asset": "xmr", "tx_hex": "nothex!!" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn confirmations_rejects_malformed_txid() {
    let app = require_app!();
    let (_uid, access, _r) = app.mint_session().await;
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/wallet/lws/confirmations",
            Some(&access),
            Some(json!({ "asset": "xmr", "txid": "not-a-txid" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");
}
