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

// ── Stage 3: money-in (attach-funding + funding verifier) DB-level tests ──────

use smirk_backend_core::error::AppError;
use smirk_backend_core::infra::db::NewSocialTip;

/// Create a draft tip for `uid` and return its id. `conf` = confirmations_required.
async fn make_draft(
    app: &common::TestApp,
    uid: uuid::Uuid,
    asset: &str,
    amount: i64,
    conf: i32,
    view_key: Option<&str>,
) -> uuid::Uuid {
    let new = NewSocialTip {
        sender_user_id: uid,
        asset,
        amount,
        claim_key_hash: Some(CLAIM_HASH),
        encrypted_key: None,
        tip_address: Some(BTC_ADDR),
        funding_txid: None,
        tip_view_key: view_key,
        confirmations_required: conf,
    };
    app.state
        .db
        .create_draft_social_tip(new)
        .await
        .expect("create draft")
        .id
}

#[tokio::test]
async fn attach_funding_is_idempotent_and_advances_draft() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;
    let tip_id = make_draft(&app, uid, "btc", 100_000, 0, None).await;

    // First attach: draft -> pending_confirmation, funding_txid recorded.
    let r1 = app
        .state
        .db
        .attach_funding_to_tip(tip_id, uid, "txid-aaa")
        .await
        .expect("attach");
    assert_eq!(r1.id, tip_id);
    assert_eq!(r1.status, "pending_confirmation");
    assert_eq!(r1.funding_txid.as_deref(), Some("txid-aaa"));
    assert!(!r1.funding_amount_verified);

    // Second attach, SAME txid: idempotent no-op returning the same row.
    let r2 = app
        .state
        .db
        .attach_funding_to_tip(tip_id, uid, "txid-aaa")
        .await
        .expect("attach idempotent");
    assert_eq!(r2.id, tip_id);
    assert_eq!(r2.status, "pending_confirmation");
    assert_eq!(r2.funding_txid.as_deref(), Some("txid-aaa"));
}

#[tokio::test]
async fn attach_funding_conflicting_txid_is_validation_error() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;
    let tip_id = make_draft(&app, uid, "btc", 100_000, 0, None).await;
    app.state
        .db
        .attach_funding_to_tip(tip_id, uid, "txid-first")
        .await
        .expect("attach");

    // A DIFFERENT txid on the same tip -> ValidationError (400).
    let err = app
        .state
        .db
        .attach_funding_to_tip(tip_id, uid, "txid-DIFFERENT")
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::ValidationError(_)), "expected ValidationError, got {err:?}");

    // Not-owned / unknown tip -> NotFound (404).
    let other = app.create_user().await;
    let err = app
        .state
        .db
        .attach_funding_to_tip(tip_id, other, "txid-x")
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::NotFound(_)), "expected NotFound, got {err:?}");
}

#[tokio::test]
async fn mark_verified_only_from_pending_confirmation() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;

    // A draft is NOT pending_confirmation -> mark returns None (guard misses).
    let draft_id = make_draft(&app, uid, "btc", 100_000, 0, None).await;
    let none = app
        .state
        .db
        .mark_tip_funding_verified(draft_id, 100_000)
        .await
        .expect("mark on draft");
    assert!(none.is_none(), "mark_verified on a draft must return None");

    // Attach -> pending_confirmation; verify flips it to pending + records observed.
    app.state
        .db
        .attach_funding_to_tip(draft_id, uid, "txid-v")
        .await
        .expect("attach");
    let verified = app
        .state
        .db
        .mark_tip_funding_verified(draft_id, 250_000)
        .await
        .expect("verify")
        .expect("verify returns row");
    assert_eq!(verified.status, "pending");
    assert!(verified.funding_amount_verified);
    assert_eq!(verified.funding_amount_observed, Some(250_000));

    // Re-verify -> None (funding_amount_verified guard no longer matches).
    let again = app
        .state
        .db
        .mark_tip_funding_verified(draft_id, 250_000)
        .await
        .expect("verify idempotent");
    assert!(again.is_none(), "re-verify must return None");
}

#[tokio::test]
async fn mark_mismatch_transitions_to_funding_mismatch() {
    let Some(app) = tips_app().await else { return };
    let uid = app.create_user().await;
    let tip_id = make_draft(&app, uid, "btc", 1_000_000, 0, None).await;
    app.state
        .db
        .attach_funding_to_tip(tip_id, uid, "txid-m")
        .await
        .expect("attach");

    let mismatch = app
        .state
        .db
        .mark_tip_funding_mismatch(tip_id, 10)
        .await
        .expect("mismatch")
        .expect("mismatch returns row");
    assert_eq!(mismatch.status, "funding_mismatch");
    assert!(mismatch.funding_amount_verified);
    assert_eq!(mismatch.funding_amount_observed, Some(10));

    // Idempotent, and a funding_mismatch row can never be flipped claimable.
    let again = app
        .state
        .db
        .mark_tip_funding_mismatch(tip_id, 10)
        .await
        .expect("mismatch idempotent");
    assert!(again.is_none());
    let verify_after = app
        .state
        .db
        .mark_tip_funding_verified(tip_id, 10)
        .await
        .expect("verify after mismatch");
    assert!(verify_after.is_none(), "a funding_mismatch row must not become claimable");
}

#[tokio::test]
async fn get_tips_pending_confirmation_filters() {
    let Some(app) = tips_app().await else { return };
    // Deterministic: this is the only test that creates xmr rows. Clear leftovers
    // so the query's LIMIT 50 / ORDER BY created_at window can't hide our row.
    sqlx::query("DELETE FROM social_tips WHERE asset = 'xmr'")
        .execute(app.state.db.pool())
        .await
        .expect("clear xmr rows");

    let uid = app.create_user().await;
    let vk = "0".repeat(64);

    // XMR tip: threshold 10 + funding attached -> INCLUDED.
    let xmr_id = make_draft(&app, uid, "xmr", 500, 10, Some(vk.as_str())).await;
    app.state
        .db
        .attach_funding_to_tip(xmr_id, uid, "xmrtxid")
        .await
        .expect("attach xmr");

    // XMR draft with NO funding -> EXCLUDED (funding_txid IS NULL, status draft).
    let xmr_draft = make_draft(&app, uid, "xmr", 500, 10, Some(vk.as_str())).await;

    // BTC tip: threshold 0 -> EXCLUDED (confirmations_required > 0 guard).
    let btc_id = make_draft(&app, uid, "btc", 100_000, 0, None).await;
    app.state
        .db
        .attach_funding_to_tip(btc_id, uid, "btctxid")
        .await
        .expect("attach btc");

    let xmr_pending = app
        .state
        .db
        .get_tips_pending_confirmation("xmr")
        .await
        .expect("xmr pending");
    assert!(xmr_pending.iter().any(|t| t.id == xmr_id), "funded xmr tip must be returned");
    assert!(
        !xmr_pending.iter().any(|t| t.id == xmr_draft),
        "unfunded xmr draft must be excluded"
    );

    let btc_pending = app
        .state
        .db
        .get_tips_pending_confirmation("btc")
        .await
        .expect("btc pending");
    assert!(
        !btc_pending.iter().any(|t| t.id == btc_id),
        "btc tip (threshold 0) must be excluded from the confirmation query"
    );
}
