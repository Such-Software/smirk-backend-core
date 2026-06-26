//! L1 integration: the tamper-evident privileged-action audit chain.
//!
//! One sequential test: the chain + verify are global to the table, so running
//! the link/verify and tamper/restore steps in parallel would race. It asserts
//! relative linkage (each row points at its predecessor) and chain validity
//! rather than absolute seq values (the test DB persists rows across runs).

mod common;

use smirk_backend_core::models::db::NewAdminAudit;

const SECRET: &str = "admin-audit-integrity-secret-0123456789ab";

fn entry(action: &str) -> NewAdminAudit {
    NewAdminAudit {
        action: action.into(),
        actor_kind: "cli".into(),
        actor_pubkey_prefix: Some("aabbccdd".into()),
        target: None,
        details: Some(serde_json::json!({ "k": action })),
        ip_address: None,
    }
}

#[tokio::test]
async fn chain_links_verifies_and_detects_tampering() {
    let app = require_app!();
    let db = &app.state.db;

    // Appends are monotonic and linked.
    let a = db
        .record_admin_audit(&entry("admin_login"), SECRET)
        .await
        .unwrap();
    let b = db
        .record_admin_audit(&entry("admin_key_added"), SECRET)
        .await
        .unwrap();
    assert_eq!(b.seq, a.seq + 1);
    assert_eq!(b.prev_hash, a.row_hash);

    // The chain verifies under the correct secret, not a different one.
    assert!(db.verify_admin_audit_chain(SECRET).await.unwrap());
    assert!(!db.verify_admin_audit_chain("WRONG").await.unwrap());

    // An edited row without re-hashing breaks the chain...
    sqlx::query("UPDATE admin_audit_logs SET action = 'tampered' WHERE id = $1")
        .bind(b.id)
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        !db.verify_admin_audit_chain(SECRET).await.unwrap(),
        "edited row breaks the chain"
    );

    // ...and restoring the exact value makes it whole again (and leaves the
    // shared table valid for later runs).
    sqlx::query("UPDATE admin_audit_logs SET action = $2 WHERE id = $1")
        .bind(b.id)
        .bind(&b.action)
        .execute(db.pool())
        .await
        .unwrap();
    assert!(db.verify_admin_audit_chain(SECRET).await.unwrap());
}
