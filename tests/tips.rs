//! Public social-tips route tests (Stage 2: create / get-public / get-sent /
//! cancel). Self-skips when `TEST_DATABASE_URL` is unset (see `tests/common`).

mod common;

use axum::http::StatusCode;
use serde_json::json;

/// Boot the app with tips ENABLED + a share base configured (BTC is on by
/// default in the test config). Returns None (skip) when no test DB.
async fn tips_app() -> Option<common::TestApp> {
    common::try_app_with(|c| {
        c.features.tips = true;
        c.tip_share_base = Some("https://tips.example".into());
    })
    .await
}

/// A valid SHA256 hash shape: exactly 64 hex chars (4 × 16).
const CLAIM_HASH: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const ENC_KEY_HEX: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const BTC_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

fn draft_body() -> serde_json::Value {
    json!({
        "asset": "btc",
        "amount": 100_000,
        "is_public": true,
        "claim_key_hash": CLAIM_HASH,
        "encrypted_key": ENC_KEY_HEX,
        "tip_address": BTC_ADDR,
    })
}

#[tokio::test]
async fn public_tip_draft_create_get_cancel_flow() {
    let Some(app) = tips_app().await else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let (_uid, token, _refresh) = app.mint_session().await;

    // 1. Create a draft (no funding_txid) -> draft + share_url.
    let (status, body) = app
        .request("POST", "/api/v1/tips/social", Some(&token), Some(draft_body()))
        .await;
    assert_eq!(status, StatusCode::OK, "create: {body}");
    assert_eq!(body["status"], "draft");
    let tip_id = body["tip_id"].as_str().expect("tip_id").to_string();
    assert_eq!(body["share_url"], format!("https://tips.example/{tip_id}"));

    // 2. Public read (UNAUTH) surfaces it and is not yet claimable.
    let (status, pub_body) = app
        .request("GET", &format!("/api/v1/tips/social/{tip_id}/public"), None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "get_public: {pub_body}");
    assert_eq!(pub_body["is_public"], true);
    assert_eq!(pub_body["is_claimable"], false);
    assert_eq!(pub_body["encrypted_key"], ENC_KEY_HEX);
    assert_eq!(pub_body["tip_address"], BTC_ADDR);

    // 3. Unknown id -> 404 (not 200-with-nulls).
    let (status, _) = app
        .request(
            "GET",
            "/api/v1/tips/social/00000000-0000-0000-0000-000000000000/public",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 4. Cancel the draft (owner) -> {ok:true}.
    let (status, cancel_body) = app
        .request("POST", &format!("/api/v1/tips/social/{tip_id}/cancel"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "cancel: {cancel_body}");
    assert_eq!(cancel_body["ok"], true);

    // 5. Cancelling again -> 404 (no longer a draft).
    let (status, _) = app
        .request("POST", &format!("/api/v1/tips/social/{tip_id}/cancel"), Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 6. Sent list shows the tip as cancelled.
    let (status, sent) = app
        .request("GET", "/api/v1/tips/social/sent", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "sent: {sent}");
    let tips = sent["tips"].as_array().expect("tips array");
    let found = tips.iter().find(|t| t["id"] == tip_id).expect("tip in sent list");
    assert_eq!(found["status"], "cancelled");
    assert_eq!(found["is_public"], true);
}

#[tokio::test]
async fn db_create_draft_roundtrips_all_columns() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;
    use smirk_backend_core::infra::db::NewSocialTip;
    let enc = hex::decode("cdcd").unwrap();
    let new = NewSocialTip {
        sender_user_id: uid,
        asset: "btc",
        amount: 100_000,
        claim_key_hash: Some(CLAIM_HASH),
        encrypted_key: Some(&enc),
        tip_address: Some(BTC_ADDR),
        funding_txid: None,
        tip_view_key: None,
        confirmations_required: 0,
    };
    // Exercises the full 31-column FromRow decode on RETURNING.
    let row = app.state.db.create_draft_social_tip(new).await.expect("create draft");
    assert_eq!(row.status, "draft");
    assert_eq!(row.amount, 100_000);
    assert!(row.is_public);
    assert_eq!(row.encrypted_key.as_deref(), Some(&[0xcd, 0xcd][..]));
}

#[tokio::test]
async fn targeted_tip_is_rejected() {
    let Some(app) = tips_app().await else { return };
    let (_uid, token, _r) = app.mint_session().await;
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/tips/social",
            Some(&token),
            Some(json!({
                "asset": "btc", "amount": 100, "is_public": false,
                "platform": "telegram", "username": "bob",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "targeted must be rejected: {body}");
}

#[tokio::test]
async fn create_requires_positive_amount_and_claim_hash() {
    let Some(app) = tips_app().await else { return };
    let (_uid, token, _r) = app.mint_session().await;

    // Non-positive amount.
    let mut b = draft_body();
    b["amount"] = json!(0);
    let (status, _) = app.request("POST", "/api/v1/tips/social", Some(&token), Some(b)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Missing claim_key_hash on a public tip.
    let mut b = draft_body();
    b.as_object_mut().unwrap().remove("claim_key_hash");
    let (status, _) = app.request("POST", "/api/v1/tips/social", Some(&token), Some(b)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tips_disabled_returns_400() {
    // Default config: FEATURE_TIPS off.
    let Some(app) = common::try_app().await else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let (_uid, token, _r) = app.mint_session().await;
    let (status, _) = app
        .request("POST", "/api/v1/tips/social", Some(&token), Some(draft_body()))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "tips off must 400");
}
