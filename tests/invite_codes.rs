//! L1: invite-code registration gate.
//!
//! The security-critical invariant is **atomic single-use**: a code redeems at
//! most ONE registration, even under concurrent submission (otherwise one invite
//! grants unbounded Sybil registrations). The redemption is a single-statement
//! `UPDATE ... WHERE used_at IS NULL ... RETURNING`, so the database enforces it;
//! these tests lock that in (incl. a concurrency race).

mod common;

use std::sync::Arc;

use smirk_backend_core::core::invite::{generate_invite_code, hash_invite_code};

#[tokio::test]
async fn invite_code_is_single_use() {
    let app = require_app!();
    let hash = hash_invite_code(&generate_invite_code());
    app.state
        .db
        .insert_invite_code(&hash, Some("test-batch"))
        .await
        .unwrap();

    assert!(
        app.state.db.claim_invite_code(&hash).await.unwrap(),
        "first redemption must succeed"
    );
    assert!(
        !app.state.db.claim_invite_code(&hash).await.unwrap(),
        "a reused code must be rejected"
    );
}

#[tokio::test]
async fn unknown_invite_code_is_rejected() {
    let app = require_app!();
    let unknown = hash_invite_code(&generate_invite_code());
    assert!(
        !app.state.db.claim_invite_code(&unknown).await.unwrap(),
        "a never-minted code must be rejected"
    );
}

#[tokio::test]
async fn concurrent_claims_redeem_at_most_once() {
    let app = require_app!();
    let hash = hash_invite_code(&generate_invite_code());
    app.state.db.insert_invite_code(&hash, None).await.unwrap();

    // Fire many concurrent redemptions of the SAME code; exactly one may win.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let state = Arc::clone(&app.state);
        let h = hash.clone();
        handles.push(tokio::spawn(async move {
            state.db.claim_invite_code(&h).await.unwrap()
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
        "exactly one concurrent claim may redeem a single-use code"
    );
}

#[tokio::test]
async fn unused_count_is_queryable_and_nonnegative() {
    // The unused count is a global doctor metric, so under parallel tests we
    // can't assert exact deltas (siblings mint/claim concurrently). We assert it
    // is queryable and reflects at least our own still-unused code; the "claimed
    // codes are excluded" property is the same `used_at IS NULL` predicate the
    // single-use test already locks in.
    let app = require_app!();
    app.state
        .db
        .insert_invite_code(&hash_invite_code(&generate_invite_code()), None)
        .await
        .unwrap();
    assert!(
        app.state.db.unused_invite_code_count().await.unwrap() >= 1,
        "count must include the just-minted unused code"
    );
}
