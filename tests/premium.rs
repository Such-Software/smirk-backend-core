//! Premium tier — L1 integration (the payment-critical DB layer + feature gate).
//!
//! Self-skips when `TEST_DATABASE_URL` is unset (see `tests/common`). The pure
//! admission logic is unit-tested in `infra::relay::policy`; these cover the parts
//! that only surface against a real database: single-use activation, stacking,
//! cross-user binding, membership-by-expiry, and the endpoint feature gate.

mod common;

use axum::http::StatusCode;
use serde_json::json;
use smirk_backend_core::models::db::NewUser;
use uuid::Uuid;

fn new_user_with_npub(npub: Option<String>) -> NewUser {
    NewUser {
        username: None,
        pubkey_hash: Some(format!("pk-{}", Uuid::new_v4())),
        nostr_pubkey: npub,
        wallet_birthday: None,
        seed_fingerprint: None,
        xmr_start_height: None,
        wow_start_height: None,
    }
}

#[tokio::test]
async fn activate_premium_is_single_use_and_stacks() {
    let app = require_app!();
    let db = &app.state.db;
    let user_id = app.create_user().await;

    db.insert_premium_invoice("inv-a", user_id, "btcpay", "quarter", 90, "5", "USD")
        .await
        .unwrap();
    db.insert_premium_invoice("inv-b", user_id, "btcpay", "quarter", 90, "5", "USD")
        .await
        .unwrap();
    assert_eq!(
        db.count_unconsumed_premium_invoices(user_id).await.unwrap(),
        2
    );

    // First activation grants a future expiry.
    let until1 = db
        .activate_premium("inv-a", user_id, 90)
        .await
        .unwrap()
        .expect("first activation grants");
    assert!(until1 > chrono::Utc::now());

    // Re-activating the SAME invoice is a no-op (single-use) — no double grant.
    assert!(db
        .activate_premium("inv-a", user_id, 90)
        .await
        .unwrap()
        .is_none());

    // A second invoice STACKS from the current expiry.
    let until2 = db
        .activate_premium("inv-b", user_id, 90)
        .await
        .unwrap()
        .expect("second activation grants");
    assert!(until2 > until1, "second plan extends the window");

    assert_eq!(db.get_premium_until(user_id).await.unwrap(), Some(until2));
    assert_eq!(
        db.count_unconsumed_premium_invoices(user_id).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn activate_premium_rejects_cross_user_invoice() {
    let app = require_app!();
    let db = &app.state.db;
    let owner = app.create_user().await;
    let attacker = app.create_user().await;
    db.insert_premium_invoice("inv-x", owner, "btcpay", "quarter", 90, "5", "USD")
        .await
        .unwrap();

    // Another user cannot activate the owner's invoice; it stays unconsumed.
    assert!(db
        .activate_premium("inv-x", attacker, 90)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.count_unconsumed_premium_invoices(owner).await.unwrap(),
        1
    );
    assert!(db.get_premium_until(attacker).await.unwrap().is_none());
}

#[tokio::test]
async fn is_premium_npub_respects_membership_and_expiry() {
    let app = require_app!();
    let db = &app.state.db;
    let npub = "a".repeat(64);
    let user = db
        .create_user(new_user_with_npub(Some(npub.clone())))
        .await
        .unwrap();

    // Not premium until granted.
    assert!(!db.is_premium_npub(&npub).await.unwrap());
    db.extend_premium(user.id, 90).await.unwrap();
    assert!(db.is_premium_npub(&npub).await.unwrap());
    // An unrelated npub is never premium.
    assert!(!db.is_premium_npub(&"b".repeat(64)).await.unwrap());
}

#[tokio::test]
async fn premium_endpoints_gated_off_by_default() {
    let app = require_app!();
    let (_uid, access, _refresh) = app.mint_session().await;

    // Premium disabled in the default test config → invoice/activate are 400.
    let (s, _) = app
        .request(
            "POST",
            "/api/v1/premium/invoice",
            Some(&access),
            Some(json!({ "plan": "quarter" })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, _) = app
        .request(
            "POST",
            "/api/v1/premium/activate",
            Some(&access),
            Some(json!({ "invoice_id": "x" })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Status is always readable → not premium.
    let (s, body) = app
        .request("GET", "/api/v1/premium/status", Some(&access), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["active"], false);

    // No token → 401.
    let (s, _) = app
        .request("GET", "/api/v1/premium/status", None, None)
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
