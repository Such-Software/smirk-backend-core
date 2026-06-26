//! L1 integration: the admin auth flow on the loopback plane — challenge → sign
//! → verify → guarded /admin/me → refresh (jti rotation) → logout → replay.
//!
//! One sequential test: it enables the admin surface via process env, so running
//! it alongside others in the same binary would race the config.

mod common;

use axum::http::StatusCode;
use base64::Engine;
use k256::schnorr::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use smirk_backend_core::core::crypto::nip98::{descriptor_sha256, request_descriptor};
use smirk_backend_core::models::db::NewAdminKey;

const NIP98_KIND: u32 = 27235;

/// A fresh, valid schnorr signer (random per run, so the shared test DB's unique
/// active-pubkey constraint never collides across runs).
fn random_signer() -> SigningKey {
    loop {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        if let Ok(sk) = SigningKey::from_bytes(&b) {
            return sk;
        }
    }
}

/// A random 64-char lowercase hex pubkey (format-valid; no curve point needed for
/// allowlist entries that are never signed with in this test).
fn random_pubkey_hex() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Build a `Nostr <base64(event)>` admin_login signed-action token.
#[allow(clippy::too_many_arguments)]
fn sign_admin_login(
    sk: &SigningKey,
    url: &str,
    challenge: &str,
    payload: &str,
    instance_id: &str,
    created_at: i64,
) -> String {
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    let tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), "POST".to_string()],
        vec!["purpose".to_string(), "admin_login".to_string()],
        vec!["challenge".to_string(), challenge.to_string()],
        vec!["payload".to_string(), payload.to_string()],
        vec!["instance_id".to_string(), instance_id.to_string()],
    ];
    let serial = serde_json::to_string(&serde_json::json!([
        0, pk_hex, created_at, NIP98_KIND, tags, ""
    ]))
    .unwrap();
    let id = hex::encode(Sha256::digest(serial.as_bytes()));
    let sig = sk.sign_raw(&hex::decode(&id).unwrap(), &[0u8; 32]).unwrap();
    let ev = serde_json::json!({
        "id": id, "pubkey": pk_hex, "created_at": created_at,
        "kind": NIP98_KIND, "tags": tags, "content": "", "sig": hex::encode(sig.to_bytes())
    });
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&ev).unwrap())
    )
}

#[tokio::test]
async fn admin_login_guard_refresh_logout_flow() {
    // Enable the admin surface (must precede try_app's config load).
    std::env::set_var("ADMIN_ENABLED", "true");
    std::env::set_var(
        "ADMIN_JWT_SECRET",
        "admin-jwt-secret-at-least-32-bytes-long!!",
    );
    std::env::set_var(
        "ADMIN_KEY_INTEGRITY_SECRET",
        "admin-integrity-secret-at-least-32-bytes!",
    );
    std::env::set_var("ADMIN_PUBLIC_URL", "http://127.0.0.1:8081");
    // The live-key cap + last-key revoke guard are count-based on a table the
    // shared test DB pollutes across runs/sibling suites, so they can't be
    // boundary-tested here (covered by review); raise the cap for the happy path.
    std::env::set_var("ADMIN_MAX_KEYS", "1000000");

    let app = require_app!();
    let admin = app.admin_router();
    let secret = app.state.config.admin.key_integrity_secret.clone();

    // Seed a PENDING admin key for our signer.
    let sk = random_signer();
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    app.state
        .db
        .create_admin_key(
            NewAdminKey {
                pubkey: pk_hex.clone(),
                label: Some("test".into()),
                scope: "admin".into(),
                created_by_kind: "cli".into(),
                activation_deadline: None,
            },
            &secret,
        )
        .await
        .unwrap();

    // 1. Challenge.
    let (st, body) = app
        .request_on(admin.clone(), "POST", "/admin/auth/challenge", None, None)
        .await;
    assert_eq!(st, StatusCode::OK);
    let challenge = body["challenge"].as_str().unwrap().to_string();
    let url = body["url"].as_str().unwrap().to_string();
    let instance_id = body["instance_id"].as_str().unwrap().to_string();

    // 2. Sign the admin_login action over the verify descriptor.
    let payload = descriptor_sha256(&request_descriptor("POST", "/admin/auth/verify", "", b""));
    let token = sign_admin_login(
        &sk,
        &url,
        &challenge,
        &payload,
        &instance_id,
        chrono::Utc::now().timestamp(),
    );

    // 3. Verify -> tokens.
    let (st, body) = app
        .request_on(
            admin.clone(),
            "POST",
            "/admin/auth/verify",
            None,
            Some(serde_json::json!({ "admin_token": token, "challenge": challenge })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "verify: {body:?}");
    let access = body["access_token"].as_str().unwrap().to_string();
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    // 4. Guard: /admin/me works with the access token, fails without / with a user token.
    let (st, body) = app
        .request_on(admin.clone(), "GET", "/admin/me", Some(&access), None)
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["pubkey"].as_str().unwrap(), pk_hex);

    let (st, _) = app
        .request_on(admin.clone(), "GET", "/admin/me", None, None)
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "no token rejected");

    let (_, user_access, _) = app.mint_session().await;
    let (st, _) = app
        .request_on(admin.clone(), "GET", "/admin/me", Some(&user_access), None)
        .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "user token rejected on admin plane"
    );

    // 4b. Keys CRUD as the activated admin. (The last-key revoke guard is not
    // asserted here: live-key count is global to the shared test DB and polluted
    // by sibling test files, so it cannot be forced to 1 deterministically.)
    let new_pk = random_pubkey_hex();
    let (st, body) = app
        .request_on(
            admin.clone(),
            "POST",
            "/admin/keys",
            Some(&access),
            Some(serde_json::json!({ "pubkey": new_pk, "label": "second" })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "add key: {body:?}");
    assert_eq!(body["status"].as_str().unwrap(), "pending");
    let added_id = body["id"].as_str().unwrap().to_string();

    // A malformed pubkey is rejected.
    let (st, _) = app
        .request_on(
            admin.clone(),
            "POST",
            "/admin/keys",
            Some(&access),
            Some(serde_json::json!({ "pubkey": "nothex" })),
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "bad pubkey rejected");

    // List shows at least our two keys.
    let (st, body) = app
        .request_on(admin.clone(), "GET", "/admin/keys", Some(&access), None)
        .await;
    assert_eq!(st, StatusCode::OK);
    assert!(body["keys"].as_array().unwrap().len() >= 2);

    // Rotate the added key -> a fresh pending key.
    let rot_pk = random_pubkey_hex();
    let (st, body) = app
        .request_on(
            admin.clone(),
            "POST",
            &format!("/admin/keys/{added_id}/rotate"),
            Some(&access),
            Some(serde_json::json!({ "pubkey": rot_pk })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "rotate: {body:?}");
    let rotated_id = body["id"].as_str().unwrap().to_string();

    // Revoke the rotated key (more than one live key exists, so it is permitted).
    let (st, _) = app
        .request_on(
            admin.clone(),
            "DELETE",
            &format!("/admin/keys/{rotated_id}"),
            Some(&access),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "revoke");

    // 5. Replay: the consumed challenge cannot be reused.
    let (st, _) = app
        .request_on(
            admin.clone(),
            "POST",
            "/admin/auth/verify",
            None,
            Some(serde_json::json!({ "admin_token": token, "challenge": challenge })),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "replayed challenge rejected");

    // 6. Refresh rotates the access jti: old access token stops working, new one works.
    let (st, body) = app
        .request_on(
            admin.clone(),
            "POST",
            "/admin/auth/refresh",
            None,
            Some(serde_json::json!({ "refresh_token": refresh })),
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let access2 = body["access_token"].as_str().unwrap().to_string();

    let (st, _) = app
        .request_on(admin.clone(), "GET", "/admin/me", Some(&access), None)
        .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "old access token invalid after refresh"
    );
    let (st, _) = app
        .request_on(admin.clone(), "GET", "/admin/me", Some(&access2), None)
        .await;
    assert_eq!(st, StatusCode::OK, "new access token valid");

    // 7. Logout revokes the session: the access token no longer authenticates.
    let (st, _) = app
        .request_on(
            admin.clone(),
            "POST",
            "/admin/auth/logout",
            Some(&access2),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = app
        .request_on(admin.clone(), "GET", "/admin/me", Some(&access2), None)
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "session revoked after logout");

    for k in [
        "ADMIN_ENABLED",
        "ADMIN_JWT_SECRET",
        "ADMIN_KEY_INTEGRITY_SECRET",
        "ADMIN_PUBLIC_URL",
        "ADMIN_MAX_KEYS",
    ] {
        std::env::remove_var(k);
    }
}
