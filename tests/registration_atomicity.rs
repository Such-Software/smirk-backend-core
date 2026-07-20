//! L1: registration atomicity. The gate token(s) and the new user row are
//! committed in ONE transaction (`create_user_consuming_gates`), so a failure
//! never burns a single-use token without an account being created. Covers the
//! two residual races the separate per-gate consumes left open:
//!   - a username collision must NOT burn a paid invoice / invite;
//!   - in `all` mode (invite AND payment), a failed payment consume must NOT burn
//!     the invite that was claimed earlier in the same request.

mod common;

use smirk_backend_core::core::invite::{generate_invite_code, hash_invite_code};
use smirk_backend_core::error::AppError;
use smirk_backend_core::models::db::{AssetType, NewUser};
use uuid::Uuid;

fn new_user(username: Option<&str>) -> NewUser {
    NewUser {
        username: username.map(str::to_string),
        pubkey_hash: Some(format!("pkh-{}", Uuid::new_v4())),
        nostr_pubkey: None,
        wallet_birthday: None,
        seed_fingerprint: None,
        xmr_start_height: None,
        wow_start_height: None,
    }
}

fn keys() -> Vec<(AssetType, String, Option<String>)> {
    vec![(AssetType::Btc, format!("btc-{}", Uuid::new_v4()), None)]
}

#[tokio::test]
async fn happy_path_consumes_tokens_creates_user_and_persists_keys() {
    let app = require_app!();
    let db = &app.state.db;

    let hash = hash_invite_code(&generate_invite_code());
    db.insert_invite_code(&hash, Some("atomic-test"))
        .await
        .unwrap();

    let pkh = format!("pay-pkh-{}", Uuid::new_v4());
    let invoice = format!("inv-{}", Uuid::new_v4());
    db.insert_payment_invoice(&invoice, &pkh, "test", "1000", "USD")
        .await
        .unwrap();

    let ks = keys();
    let user = db
        .create_user_consuming_gates(Some(&hash), Some((&invoice, &pkh)), new_user(None), &ks)
        .await
        .expect("gated registration commits");

    // Both single-use tokens were consumed inside the tx.
    assert!(
        !db.claim_invite_code(&hash).await.unwrap(),
        "invite must be consumed on a successful registration"
    );
    assert!(
        !db.consume_payment_invoice(&invoice, &pkh).await.unwrap(),
        "invoice must be consumed on a successful registration"
    );
    // Keys were persisted in the same tx.
    assert!(
        !db.get_user_keys(user.id).await.unwrap().is_empty(),
        "chain keys must be persisted"
    );
}

#[tokio::test]
async fn username_collision_rolls_back_the_invite() {
    let app = require_app!();
    let db = &app.state.db;

    // Occupy a username.
    let taken = format!("taken-{}", Uuid::new_v4());
    db.create_user(new_user(Some(&taken))).await.unwrap();

    // A fresh, claimable invite.
    let hash = hash_invite_code(&generate_invite_code());
    db.insert_invite_code(&hash, Some("atomic-test"))
        .await
        .unwrap();

    // Register a NEW wallet that collides on the taken username.
    let err = db
        .create_user_consuming_gates(Some(&hash), None, new_user(Some(&taken)), &keys())
        .await
        .expect_err("a colliding username must fail the registration");
    assert!(
        matches!(err, AppError::Conflict(_)),
        "expected 409, got {err:?}"
    );

    // The invite must NOT have been burned — the tx rolled back.
    assert!(
        db.claim_invite_code(&hash).await.unwrap(),
        "the invite must be intact after a username collision"
    );
}

#[tokio::test]
async fn failed_payment_consume_does_not_burn_the_invite() {
    let app = require_app!();
    let db = &app.state.db;

    // A fresh, claimable invite.
    let hash = hash_invite_code(&generate_invite_code());
    db.insert_invite_code(&hash, Some("atomic-test"))
        .await
        .unwrap();

    // A payment invoice that is ALREADY spent (simulates losing the consume race
    // in `all` mode after the invite was claimed).
    let pkh = format!("pay-pkh-{}", Uuid::new_v4());
    let invoice = format!("inv-{}", Uuid::new_v4());
    db.insert_payment_invoice(&invoice, &pkh, "test", "1000", "USD")
        .await
        .unwrap();
    assert!(
        db.consume_payment_invoice(&invoice, &pkh).await.unwrap(),
        "pre-consume the invoice so the registration's payment consume will fail"
    );

    // all-mode conjunction: consume invite THEN payment. The payment consume fails
    // (already spent), which must roll the invite claim back too.
    let err = db
        .create_user_consuming_gates(Some(&hash), Some((&invoice, &pkh)), new_user(None), &keys())
        .await
        .expect_err("an already-spent payment must fail the registration");
    assert!(
        matches!(err, AppError::ValidationError(_)),
        "expected the already-used literal, got {err:?}"
    );

    // The invite must NOT have been burned by the failed payment consume.
    assert!(
        db.claim_invite_code(&hash).await.unwrap(),
        "the invite must be intact when the payment consume fails"
    );
}
