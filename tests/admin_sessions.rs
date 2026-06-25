//! L1 integration: the admin_sessions lifecycle against real Postgres —
//! create, lookup-by-jti, jti rotation on refresh, logout, and key-cascade
//! revocation.

mod common;

use chrono::{Duration, Utc};
use smirk_backend_core::models::db::{NewAdminKey, NewAdminSession};
use uuid::Uuid;

const SECRET: &str = "admin-key-integrity-secret-0123456789ab";

async fn make_key(db: &smirk_backend_core::infra::db::Database) -> (Uuid, String) {
    let pk = format!("{:0>64}", Uuid::new_v4().simple());
    let key = db
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
    (key.id, pk)
}

fn new_session(id: Uuid, key_id: Uuid, pk: &str, jti: &str) -> NewAdminSession {
    NewAdminSession {
        id,
        admin_key_id: key_id,
        pubkey: pk.to_string(),
        refresh_token_hash: format!("hash-{jti}"),
        access_jti: jti.to_string(),
        device_info: None,
        ip_address: None,
        expires_at: Utc::now() + Duration::hours(8),
    }
}

#[tokio::test]
async fn create_lookup_rotate_and_logout() {
    let app = require_app!();
    let db = &app.state.db;
    let (key_id, pk) = make_key(db).await;
    let sid = Uuid::new_v4();

    db.create_admin_session(new_session(sid, key_id, &pk, "jti-1"))
        .await
        .unwrap();

    // Guard lookup by the access jti.
    let found = db
        .find_active_admin_session_by_jti("jti-1")
        .await
        .unwrap()
        .expect("live session by jti");
    assert_eq!(found.id, sid);

    // Refresh rotates the jti: the old one stops matching, the new one matches.
    db.rotate_admin_session_jti(sid, "jti-2")
        .await
        .unwrap()
        .expect("rotated");
    assert!(db
        .find_active_admin_session_by_jti("jti-1")
        .await
        .unwrap()
        .is_none());
    assert!(db
        .find_active_admin_session_by_jti("jti-2")
        .await
        .unwrap()
        .is_some());

    // Logout revokes the session.
    assert!(db.revoke_admin_session(sid).await.unwrap());
    assert!(db
        .find_active_admin_session_by_jti("jti-2")
        .await
        .unwrap()
        .is_none());
    // Re-revoke is a no-op.
    assert!(!db.revoke_admin_session(sid).await.unwrap());
}

#[tokio::test]
async fn key_revocation_cascades_to_sessions() {
    let app = require_app!();
    let db = &app.state.db;
    let (key_id, pk) = make_key(db).await;

    let s1 = Uuid::new_v4();
    let s2 = Uuid::new_v4();
    db.create_admin_session(new_session(s1, key_id, &pk, "c-1"))
        .await
        .unwrap();
    db.create_admin_session(new_session(s2, key_id, &pk, "c-2"))
        .await
        .unwrap();

    // Cascade revokes both live sessions for the key.
    let n = db.revoke_admin_sessions_for_key(key_id).await.unwrap();
    assert_eq!(n, 2);
    assert!(db
        .find_active_admin_session_by_id(s1)
        .await
        .unwrap()
        .is_none());
    assert!(db
        .find_active_admin_session_by_id(s2)
        .await
        .unwrap()
        .is_none());
}
