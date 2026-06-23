//! L1 integration: BTC/LTC wallet endpoints through the real router.
//!
//! These assert the deterministic, no-network paths: the JWT gate, asset
//! validation, and broadcast tx-hex validation — all of which resolve before any
//! Electrum call. The funded/networked happy paths (real balance/broadcast) live
//! in the separate gitignored L3 harness.

mod common;

use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn balance_requires_a_token() {
    let app = require_app!();
    let (status, _) = app
        .request(
            "POST",
            "/api/v1/wallet/utxo/balance",
            None,
            Some(
                json!({ "asset": "btc", "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" }),
            ),
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
            "/api/v1/wallet/utxo/balance",
            Some(&access),
            Some(json!({ "asset": "doge", "address": "x" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn broadcast_requires_a_token() {
    let app = require_app!();
    let (status, _) = app
        .request(
            "POST",
            "/api/v1/wallet/utxo/broadcast",
            None,
            Some(json!({ "asset": "btc", "tx_hex": "deadbeef" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn broadcast_rejects_malformed_tx_hex() {
    let app = require_app!();
    let (_uid, access, _r) = app.mint_session().await;
    // Authed + valid asset, but the tx hex is non-hex -> 400 before any network.
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/wallet/utxo/broadcast",
            Some(&access),
            Some(json!({ "asset": "btc", "tx_hex": "nothex!!" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn fee_requires_a_token() {
    let app = require_app!();
    let (status, _) = app
        .request(
            "POST",
            "/api/v1/wallet/utxo/fee",
            None,
            Some(json!({ "asset": "btc", "blocks": 6 })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
