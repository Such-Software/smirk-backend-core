//! L1: pay-to-register payment-invoice binding + single-use.
//!
//! Two security-critical invariants, both enforced by a single-statement
//! `UPDATE ... WHERE consumed_at IS NULL AND pubkey_hash = $ ... RETURNING`:
//!   * BINDING — an invoice bound to one `pubkey_hash` can NEVER be consumed for
//!     a different identity (else a settled invoice could be replayed to register
//!     someone else's wallet);
//!   * ATOMIC SINGLE-USE — a settled invoice grants at most ONE registration,
//!     even under concurrent completion.
//!
//! These tests lock both in (incl. a concurrency race).

mod common;

use std::sync::Arc;

use uuid::Uuid;

/// A fresh (invoice_id, pubkey_hash) pair, unique per call so the tests stay
/// isolated under parallel execution against a shared database.
fn ids() -> (String, String) {
    (
        format!("inv-{}", Uuid::new_v4()),
        format!("pk-{}", Uuid::new_v4()),
    )
}

#[tokio::test]
async fn insert_then_get_roundtrips() {
    let app = require_app!();
    let (invoice_id, pubkey_hash) = ids();
    app.state
        .db
        .insert_payment_invoice(&invoice_id, &pubkey_hash, "btcpay", "0.01", "XMR")
        .await
        .unwrap();

    let row = app
        .state
        .db
        .get_payment_invoice(&invoice_id)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(row.pubkey_hash, pubkey_hash);
    assert_eq!(row.amount, "0.01");
    assert_eq!(row.currency, "XMR");
    assert!(row.consumed_at.is_none(), "a fresh invoice is unspent");
}

#[tokio::test]
async fn get_unknown_invoice_is_none() {
    let app = require_app!();
    let (invoice_id, _) = ids();
    assert!(app
        .state
        .db
        .get_payment_invoice(&invoice_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn consume_is_single_use() {
    let app = require_app!();
    let (invoice_id, pubkey_hash) = ids();
    app.state
        .db
        .insert_payment_invoice(&invoice_id, &pubkey_hash, "btcpay", "0.01", "XMR")
        .await
        .unwrap();

    assert!(
        app.state
            .db
            .consume_payment_invoice(&invoice_id, &pubkey_hash)
            .await
            .unwrap(),
        "first consume must succeed"
    );
    assert!(
        !app.state
            .db
            .consume_payment_invoice(&invoice_id, &pubkey_hash)
            .await
            .unwrap(),
        "a reused invoice must be rejected"
    );
    let row = app
        .state
        .db
        .get_payment_invoice(&invoice_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        row.consumed_at.is_some(),
        "consumed invoice records the time"
    );
}

#[tokio::test]
async fn consume_bound_to_other_identity_is_rejected() {
    let app = require_app!();
    let (invoice_id, pubkey_hash) = ids();
    app.state
        .db
        .insert_payment_invoice(&invoice_id, &pubkey_hash, "btcpay", "0.01", "XMR")
        .await
        .unwrap();

    // A DIFFERENT identity cannot consume this invoice...
    let (_, attacker) = ids();
    assert!(
        !app.state
            .db
            .consume_payment_invoice(&invoice_id, &attacker)
            .await
            .unwrap(),
        "an invoice bound to one identity is not consumable by another"
    );
    // ...and the mis-bound attempt did NOT burn it — the rightful owner still can.
    assert!(
        app.state
            .db
            .consume_payment_invoice(&invoice_id, &pubkey_hash)
            .await
            .unwrap(),
        "the bound identity can still consume after a mis-bound attempt"
    );
}

#[tokio::test]
async fn concurrent_consume_redeems_at_most_once() {
    let app = require_app!();
    let (invoice_id, pubkey_hash) = ids();
    app.state
        .db
        .insert_payment_invoice(&invoice_id, &pubkey_hash, "btcpay", "0.01", "XMR")
        .await
        .unwrap();

    // Fire many concurrent consumes of the SAME invoice; exactly one may win.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let state = Arc::clone(&app.state);
        let inv = invoice_id.clone();
        let pk = pubkey_hash.clone();
        handles.push(tokio::spawn(async move {
            state.db.consume_payment_invoice(&inv, &pk).await.unwrap()
        }));
    }
    let mut wins = 0;
    for handle in handles {
        if handle.await.unwrap() {
            wins += 1;
        }
    }
    assert_eq!(
        wins, 1,
        "exactly one concurrent consume may redeem a single-use invoice"
    );
}
