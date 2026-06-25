//! L1 integration: the admin allowlist + integrity MAC against real Postgres.
//! The load-bearing test is `tampered_revoke_flip_is_rejected`: a DB-write
//! attacker who clears `revoked_at` via raw SQL must not resurrect the key.

mod common;

use smirk_backend_core::models::db::NewAdminKey;
use uuid::Uuid;

const SECRET: &str = "admin-key-integrity-secret-0123456789ab";

fn new_key(pubkey: &str) -> NewAdminKey {
    NewAdminKey {
        pubkey: pubkey.to_string(),
        label: Some("test".into()),
        scope: "admin".into(),
        created_by_kind: "cli".into(),
        activation_deadline: None,
    }
}

#[tokio::test]
async fn create_then_active_lookup_verifies_mac() {
    let app = require_app!();
    let db = &app.state.db;
    let pk = format!("{:0>64}", Uuid::new_v4().simple());

    let created = db.create_admin_key(new_key(&pk), SECRET).await.unwrap();
    assert!(created.activated_at.is_none(), "starts pending");

    let active = db
        .get_active_admin_key(&pk, SECRET)
        .await
        .unwrap()
        .expect("active key with valid MAC");
    assert_eq!(active.id, created.id);

    // A different integrity secret must NOT validate the row.
    assert!(
        db.get_active_admin_key(&pk, "WRONG-SECRET")
            .await
            .unwrap()
            .is_none(),
        "wrong secret rejected"
    );
}

#[tokio::test]
async fn duplicate_active_pubkey_conflicts() {
    let app = require_app!();
    let db = &app.state.db;
    let pk = format!("{:0>64}", Uuid::new_v4().simple());

    db.create_admin_key(new_key(&pk), SECRET).await.unwrap();
    let err = db.create_admin_key(new_key(&pk), SECRET).await.unwrap_err();
    assert!(
        matches!(err, smirk_backend_core::error::AppError::Conflict(_)),
        "second active key for the same pubkey is a conflict"
    );
}

#[tokio::test]
async fn revoke_removes_from_active_set() {
    let app = require_app!();
    let db = &app.state.db;
    let pk = format!("{:0>64}", Uuid::new_v4().simple());

    let key = db.create_admin_key(new_key(&pk), SECRET).await.unwrap();
    let revoked = db.revoke_admin_key(key.id, SECRET).await.unwrap().unwrap();
    assert!(revoked.revoked_at.is_some());
    assert!(db
        .get_active_admin_key(&pk, SECRET)
        .await
        .unwrap()
        .is_none());
    // Re-revoking is a no-op (already revoked).
    assert!(db.revoke_admin_key(key.id, SECRET).await.unwrap().is_none());
    // After revoke the pubkey is free for a fresh active key (partial index).
    assert!(db.create_admin_key(new_key(&pk), SECRET).await.is_ok());
}

#[tokio::test]
async fn activate_flips_pending_once() {
    let app = require_app!();
    let db = &app.state.db;
    let pk = format!("{:0>64}", Uuid::new_v4().simple());

    let key = db.create_admin_key(new_key(&pk), SECRET).await.unwrap();
    let activated = db
        .activate_admin_key(key.id, SECRET)
        .await
        .unwrap()
        .unwrap();
    assert!(activated.activated_at.is_some());
    // Still MAC-valid after the activation rewrite.
    assert!(db
        .get_active_admin_key(&pk, SECRET)
        .await
        .unwrap()
        .is_some());
    // Activating again is a no-op (no longer pending).
    assert!(db
        .activate_admin_key(key.id, SECRET)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn tampered_revoke_flip_is_rejected() {
    let app = require_app!();
    let db = &app.state.db;
    let pk = format!("{:0>64}", Uuid::new_v4().simple());

    let key = db.create_admin_key(new_key(&pk), SECRET).await.unwrap();
    db.revoke_admin_key(key.id, SECRET).await.unwrap();

    // Attacker clears revoked_at via raw SQL WITHOUT recomputing the MAC.
    sqlx::query("UPDATE admin_keys SET revoked_at = NULL WHERE id = $1")
        .bind(key.id)
        .execute(db.pool())
        .await
        .unwrap();

    // The row is now "active" by column, but its MAC was computed for the
    // revoked state, so the guard's lookup must reject it.
    assert!(
        db.get_active_admin_key(&pk, SECRET)
            .await
            .unwrap()
            .is_none(),
        "un-revoke tamper rejected by integrity MAC"
    );
}
