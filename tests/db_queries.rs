//! L1 integration: the db query layer against a real Postgres. Validates the
//! migrations, peppered identity columns, UNIQUE->409 mapping, and the
//! session/key lifecycles that unit tests cannot reach without a database.

mod common;

use chrono::{Duration, Utc};
use smirk_backend_core::error::AppError;
use smirk_backend_core::models::db::{AssetType, NewSession, NewUser, NewUserKey};
use uuid::Uuid;

fn new_user(pubkey_hash: &str) -> NewUser {
    NewUser {
        username: None,
        pubkey_hash: Some(pubkey_hash.to_string()),
        nostr_pubkey: None,
        wallet_birthday: None,
        seed_fingerprint: None,
        xmr_start_height: None,
        wow_start_height: None,
    }
}

#[tokio::test]
async fn create_user_then_peppered_lookup() {
    let app = require_app!();
    let db = &app.state.db;
    let raw = format!("pk-{}", Uuid::new_v4());

    let user = db.create_user(new_user(&raw)).await.unwrap();

    // Raw pubkey hash resolves the row (peppering is applied symmetrically).
    let found = db
        .get_user_by_pubkey_hash(&raw)
        .await
        .unwrap()
        .expect("resolved by pubkey_hash");
    assert_eq!(found.id, user.id);

    // The value stored at rest is peppered, NOT the raw input (seed-oracle fix).
    assert_ne!(found.pubkey_hash.as_deref(), Some(raw.as_str()));

    assert_eq!(
        db.get_user_by_id(user.id).await.unwrap().unwrap().id,
        user.id
    );
}

#[tokio::test]
async fn username_unique_violation_is_conflict() {
    let app = require_app!();
    let db = &app.state.db;
    let name = format!("u{}", Uuid::new_v4().simple());

    let a = db
        .create_user(new_user(&format!("pk-{}", Uuid::new_v4())))
        .await
        .unwrap();
    let b = db
        .create_user(new_user(&format!("pk-{}", Uuid::new_v4())))
        .await
        .unwrap();

    db.set_username(a.id, &name).await.unwrap();
    let err = db.set_username(b.id, &name).await.unwrap_err();
    assert!(
        matches!(err, AppError::Conflict(_)),
        "expected 409 Conflict, got {err:?}"
    );
}

#[tokio::test]
async fn session_create_lookup_revoke() {
    let app = require_app!();
    let db = &app.state.db;
    let user = db
        .create_user(new_user(&format!("pk-{}", Uuid::new_v4())))
        .await
        .unwrap();
    let hash = format!("rh-{}", Uuid::new_v4());

    let sess = db
        .create_session(NewSession {
            user_id: user.id,
            refresh_token_hash: hash.clone(),
            platform: "extension".to_string(),
            device_info: None,
            ip_address: None,
            expires_at: Utc::now() + Duration::days(30),
        })
        .await
        .unwrap();

    assert!(db.get_session_by_token_hash(&hash).await.unwrap().is_some());

    // First revoke succeeds (was active); the lookup then excludes it.
    assert!(db.revoke_session(sess.id).await.unwrap());
    assert!(db.get_session_by_token_hash(&hash).await.unwrap().is_none());
    // Second revoke is a no-op (already revoked) -> false, disambiguating races.
    assert!(!db.revoke_session(sess.id).await.unwrap());
}

#[tokio::test]
async fn user_key_upsert_list_delete() {
    let app = require_app!();
    let db = &app.state.db;
    let user = db
        .create_user(new_user(&format!("pk-{}", Uuid::new_v4())))
        .await
        .unwrap();

    let mk = |pk: &str| NewUserKey {
        user_id: user.id,
        asset: AssetType::Btc,
        public_key: pk.to_string(),
        public_spend_key: None,
        key_type: "primary".to_string(),
    };

    db.upsert_user_key(mk("pk1")).await.unwrap();
    // Same (user, asset, key_type) upserts in place rather than duplicating.
    db.upsert_user_key(mk("pk2")).await.unwrap();

    let keys = db.get_user_keys(user.id).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].public_key, "pk2");

    assert!(db.delete_user_key(user.id, AssetType::Btc).await.unwrap());
    assert!(db.get_user_keys(user.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn restore_attempts_count_and_pepper() {
    let app = require_app!();
    let db = &app.state.db;
    let fp = format!("fp-{}", Uuid::new_v4());

    assert_eq!(db.count_failed_restore_attempts(&fp).await.unwrap(), 0);
    db.record_restore_attempt(&fp, Some("203.0.113.7"), false)
        .await
        .unwrap();
    db.record_restore_attempt(&fp, Some("203.0.113.7"), false)
        .await
        .unwrap();
    assert_eq!(db.count_failed_restore_attempts(&fp).await.unwrap(), 2);
}
