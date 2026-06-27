//! L1 integration: the first-run bootstrap latch (operator §3.2).
//!
//! The latch is a singleton (id=1) only this suite reads (main's boot logic does
//! not run under the harness), so this one sequential test owns it and drives the
//! state machine deterministically. The bootstrap SUCCESS path needs an empty
//! admin allowlist, which the shared test DB cannot guarantee; instead this
//! asserts bootstrap's refusal guard (with a guaranteed active admin) — the
//! success path's pieces (admin insert MAC + latch MAC) are covered elsewhere.

mod common;

use smirk_backend_core::infra::db::SetupState;
use smirk_backend_core::models::db::NewAdminKey;
use uuid::Uuid;

const SECRET: &str = "server-config-integrity-secret-0123456789ab";

#[tokio::test]
async fn latch_state_machine_and_tamper_detection() {
    let app = require_app!();
    let db = &app.state.db;

    // Own the singleton: no row => Fresh.
    sqlx::query("DELETE FROM server_config WHERE id = 1")
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(
        db.read_setup_state(SECRET).await.unwrap(),
        SetupState::Fresh
    );

    // Adoption path: init creates a valid locked latch.
    db.init_server_config(SECRET, true).await.unwrap();
    assert_eq!(
        db.read_setup_state(SECRET).await.unwrap(),
        SetupState::Locked
    );

    // Wrong secret => MAC fails => Tampered (fail-closed).
    assert_eq!(
        db.read_setup_state("WRONG-SECRET").await.unwrap(),
        SetupState::Tampered
    );

    // Raw flip of state without recomputing the MAC => Tampered (the
    // restore-to-pre-bootstrap attack).
    sqlx::query(
        "UPDATE server_config SET setup_state = 'uninitialized', bootstrap_completed_at = NULL WHERE id = 1",
    )
    .execute(db.pool())
    .await
    .unwrap();
    assert_eq!(
        db.read_setup_state(SECRET).await.unwrap(),
        SetupState::Tampered
    );

    // reset-setup recomputes the MAC => verifies again as uninitialized.
    db.reset_setup(SECRET).await.unwrap();
    assert_eq!(
        db.read_setup_state(SECRET).await.unwrap(),
        SetupState::Uninitialized
    );

    // With an active admin present, bootstrap must refuse (no second bootstrap).
    let pk = format!("{:0>64}", Uuid::new_v4().simple());
    let k = db
        .create_admin_key(
            NewAdminKey {
                pubkey: pk.clone(),
                label: None,
                scope: "admin".into(),
                created_by_kind: "cli".into(),
                activation_deadline: None,
            },
            SECRET,
        )
        .await
        .unwrap();
    db.activate_admin_key(k.id, SECRET).await.unwrap();
    assert!(
        db.bootstrap_admin(&"11".repeat(32), SECRET).await.is_err(),
        "bootstrap refused while an active admin exists"
    );
    let _ = db.revoke_admin_key(k.id, SECRET).await;
}
