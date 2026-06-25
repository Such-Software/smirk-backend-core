//! L1 integration: the unified challenge (server-nonce) store. Validates atomic
//! single-use consumption, purpose binding, and expiry against real Postgres.

mod common;

#[tokio::test]
async fn issue_then_consume_once() {
    let app = require_app!();
    let db = &app.state.db;

    let nonce = db
        .issue_challenge("admin_login", Some("pubkey-x"), 120)
        .await
        .unwrap();
    assert_eq!(nonce.len(), 64, "32-byte hex nonce");

    // First consume succeeds and returns the bound subject.
    let consumed = db
        .consume_challenge(&nonce, "admin_login")
        .await
        .unwrap()
        .expect("nonce consumes once");
    assert_eq!(consumed.subject.as_deref(), Some("pubkey-x"));

    // Second consume (replay) is rejected.
    assert!(
        db.consume_challenge(&nonce, "admin_login")
            .await
            .unwrap()
            .is_none(),
        "replay rejected"
    );
}

#[tokio::test]
async fn consume_rejects_wrong_purpose() {
    let app = require_app!();
    let db = &app.state.db;

    let nonce = db.issue_challenge("setup", None, 120).await.unwrap();
    // A nonce minted for one purpose cannot be consumed under another.
    assert!(
        db.consume_challenge(&nonce, "admin_login")
            .await
            .unwrap()
            .is_none(),
        "purpose mismatch rejected"
    );
    // The original purpose still works (the failed attempt didn't consume it).
    assert!(db
        .consume_challenge(&nonce, "setup")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn expired_nonce_is_not_consumable() {
    let app = require_app!();
    let db = &app.state.db;

    // TTL 0 => already expired by the time we consume.
    let nonce = db
        .issue_challenge("erasure_request", None, 0)
        .await
        .unwrap();
    assert!(
        db.consume_challenge(&nonce, "erasure_request")
            .await
            .unwrap()
            .is_none(),
        "expired nonce rejected"
    );
    // Sweeper removes it.
    let _ = db.delete_expired_challenges().await.unwrap();
}
