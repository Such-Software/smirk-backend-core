//! L1 integration: the Grin slatepack relay through the real router.
//!
//! The relay is pure store-and-forward (DB-backed, no chain network), so this
//! exercises the FULL lifecycle and the authorization rules end to end against a
//! real Postgres: create -> pending -> respond -> get -> finalize, plus the
//! non-party 404s.

mod common;

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

fn slate_id() -> String {
    // Grin slate ids are UUIDs (validated as such by the handler).
    Uuid::new_v4().to_string()
}

#[tokio::test]
async fn create_requires_a_token() {
    let app = require_app!();
    let (status, _) = app
        .request(
            "POST",
            "/api/v1/wallet/grin/relay/create",
            None,
            Some(json!({
                "recipient_user_id": Uuid::new_v4().to_string(),
                "slate_id": slate_id(),
                "slatepack": "BEGINSLATEPACK.abc.ENDSLATEPACK",
                "amount_nanogrin": 1000
            })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_rejects_unregistered_recipient() {
    let app = require_app!();
    let (_uid, access, _r) = app.mint_session().await;
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/wallet/grin/relay/create",
            Some(&access),
            Some(json!({
                "recipient_user_id": Uuid::new_v4().to_string(), // not a real user
                "slate_id": slate_id(),
                "slatepack": "BEGINSLATEPACK.abc.ENDSLATEPACK",
                "amount_nanogrin": 1000
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn full_relay_lifecycle() {
    let app = require_app!();
    let (_sender_id, sender, _r1) = app.mint_session().await;
    let (recipient_id, recipient, _r2) = app.mint_session().await;
    let sid = slate_id();

    // Sender posts the slatepack to the recipient.
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/wallet/grin/relay/create",
            Some(&sender),
            Some(json!({
                "recipient_user_id": recipient_id.to_string(),
                "slate_id": sid,
                "slatepack": "BEGINSLATEPACK.sender.ENDSLATEPACK",
                "amount_nanogrin": 5000
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "pending_recipient");

    // Recipient sees it in their inbox.
    let (status, body) = app
        .request(
            "GET",
            "/api/v1/wallet/grin/relay/pending",
            Some(&recipient),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let found = body["relays"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["slate_id"] == sid);
    assert!(found, "recipient inbox should contain the relay");

    // Recipient responds.
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/wallet/grin/relay/respond",
            Some(&recipient),
            Some(json!({ "slate_id": sid, "response_slatepack": "BEGINSLATEPACK.recipient.ENDSLATEPACK" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "pending_sender");

    // Sender polls and gets the response back.
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/wallet/grin/relay/get",
            Some(&sender),
            Some(json!({ "slate_id": sid })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["response_slatepack"],
        "BEGINSLATEPACK.recipient.ENDSLATEPACK"
    );

    // Sender finalizes (records the txid; the wallet did the broadcast).
    let (status, body) = app
        .request(
            "POST",
            "/api/v1/wallet/grin/relay/finalize",
            Some(&sender),
            Some(json!({ "slate_id": sid, "tx_hash": "deadbeef" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "finalized");
    assert_eq!(body["tx_hash"], "deadbeef");
}

#[tokio::test]
async fn third_party_cannot_read_relay() {
    let app = require_app!();
    let (_sender_id, sender, _r1) = app.mint_session().await;
    let (recipient_id, _recipient, _r2) = app.mint_session().await;
    let (_third_id, third, _r3) = app.mint_session().await;
    let sid = slate_id();

    app.request(
        "POST",
        "/api/v1/wallet/grin/relay/create",
        Some(&sender),
        Some(json!({
            "recipient_user_id": recipient_id.to_string(),
            "slate_id": sid,
            "slatepack": "BEGINSLATEPACK.x.ENDSLATEPACK",
            "amount_nanogrin": 1
        })),
    )
    .await;

    // A non-party gets 404 (no existence oracle), not 403.
    let (status, _) = app
        .request(
            "POST",
            "/api/v1/wallet/grin/relay/get",
            Some(&third),
            Some(json!({ "slate_id": sid })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // And a non-recipient cannot respond.
    let (status, _) = app
        .request(
            "POST",
            "/api/v1/wallet/grin/relay/respond",
            Some(&third),
            Some(json!({ "slate_id": sid, "response_slatepack": "BEGINSLATEPACK.evil.ENDSLATEPACK" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
