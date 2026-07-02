//! L1 integration: the first-run bootstrap latch (operator §3.2).
//!
//! The latch is a singleton (id=1) only this suite reads (main's boot logic does
//! not run under the harness), so this one sequential test owns it and drives the
//! state machine deterministically. The bootstrap SUCCESS path needs an empty
//! admin allowlist, which the shared test DB cannot guarantee; instead this
//! asserts bootstrap's refusal guard (with a guaranteed active admin) — the
//! success path's pieces (admin insert MAC + latch MAC) are covered elsewhere.

mod common;

use smirk_backend_core::infra::db::{AddKeyOutcome, SetupState};
use smirk_backend_core::models::db::{NewAdminAudit, NewAdminKey};
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

    // ── create_admin_key_bootstrapping: a generated-key first-run (fix B) ──────
    // `create-admin-wallet` on a FRESH instance must be a COMPLETE bootstrap:
    // register the (pending) generated key AND latch `locked`, atomically.
    sqlx::query("DELETE FROM server_config WHERE id = 1")
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(
        db.read_setup_state(SECRET).await.unwrap(),
        SetupState::Fresh
    );

    let genpk = format!("{:0>64}", Uuid::new_v4().simple());
    let audit = NewAdminAudit {
        action: "admin_wallet_created".into(),
        actor_kind: "cli".into(),
        actor_pubkey_prefix: None,
        target: Some(genpk.clone()),
        details: None,
        ip_address: None,
    };
    let (outcome, latched) = db
        .create_admin_key_bootstrapping(
            NewAdminKey {
                pubkey: genpk.clone(),
                label: Some("cli-generated".into()),
                scope: "admin".into(),
                created_by_kind: "cli".into(),
                activation_deadline: None,
            },
            &audit,
            SECRET,
            i64::MAX,
        )
        .await
        .unwrap();
    assert!(
        latched,
        "a fresh instance is latched by create-admin-wallet"
    );
    assert_eq!(
        db.read_setup_state(SECRET).await.unwrap(),
        SetupState::Locked,
        "the generated-key bootstrap latches locked"
    );
    let key1 = match outcome {
        AddKeyOutcome::Created(k) => k,
        AddKeyOutcome::CapReached => panic!("unexpected cap"),
    };
    assert!(
        key1.activated_at.is_none(),
        "the generated key stays pending (activates on first login)"
    );

    // A SECOND generated key on the now-locked instance is a plain pending add —
    // it must NOT re-latch (no re-stamping bootstrap_completed_at).
    let genpk2 = format!("{:0>64}", Uuid::new_v4().simple());
    let audit2 = NewAdminAudit {
        target: Some(genpk2.clone()),
        ..audit.clone()
    };
    let (outcome2, latched2) = db
        .create_admin_key_bootstrapping(
            NewAdminKey {
                pubkey: genpk2.clone(),
                label: Some("cli-generated".into()),
                scope: "admin".into(),
                created_by_kind: "cli".into(),
                activation_deadline: None,
            },
            &audit2,
            SECRET,
            i64::MAX,
        )
        .await
        .unwrap();
    assert!(!latched2, "an already-locked instance is not re-latched");
    assert_eq!(
        db.read_setup_state(SECRET).await.unwrap(),
        SetupState::Locked
    );
    let key2 = match outcome2 {
        AddKeyOutcome::Created(k) => k,
        AddKeyOutcome::CapReached => panic!("unexpected cap"),
    };

    // Composition guard: with a live (even PENDING) key present, `setup` refuses
    // rather than seeding a confusing second admin. NOTE: on the shared test DB this
    // assertion is non-discriminating — sibling test binaries leave ACTIVE keys, so
    // it would pass under the old active-only guard too. The any-live widen is proven
    // hermetically at the query level in the db unit tests; here it documents intent.
    assert!(
        db.bootstrap_admin(&"22".repeat(32), SECRET).await.is_err(),
        "setup refuses once any live admin key exists (even pending)"
    );

    // create-admin-wallet FAILS CLOSED on a tampered latch (defers to reset-setup),
    // rather than silently re-stamping a valid `locked` latch over the tamper. We own
    // the singleton, so this is isolable: raw-flip the state without recomputing the
    // MAC (the restore-to-pre-bootstrap shape), then assert the call errors, the latch
    // is NOT healed, and the key insert was rolled back.
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
    let genpk3 = format!("{:0>64}", Uuid::new_v4().simple());
    let audit3 = NewAdminAudit {
        target: Some(genpk3.clone()),
        ..audit.clone()
    };
    let tampered_res = db
        .create_admin_key_bootstrapping(
            NewAdminKey {
                pubkey: genpk3.clone(),
                label: Some("cli-generated".into()),
                scope: "admin".into(),
                created_by_kind: "cli".into(),
                activation_deadline: None,
            },
            &audit3,
            SECRET,
            i64::MAX,
        )
        .await;
    assert!(
        tampered_res.is_err(),
        "create-admin-wallet fails closed on a tampered latch"
    );
    assert_eq!(
        db.read_setup_state(SECRET).await.unwrap(),
        SetupState::Tampered,
        "the tampered latch is NOT silently healed"
    );
    let keys = db.list_admin_keys().await.unwrap();
    assert!(
        !keys.iter().any(|k| k.pubkey == genpk3),
        "the refused call rolled back its pending key insert"
    );

    let _ = db.revoke_admin_key(key1.id, SECRET).await;
    let _ = db.revoke_admin_key(key2.id, SECRET).await;

    // Leave the owned singleton in a clean, MAC-valid state (not raw-tampered) for
    // the next run / any reader.
    db.reset_setup(SECRET).await.unwrap();
}
