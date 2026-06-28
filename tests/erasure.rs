//! L1 integration: self-service erasure (operator §5) — the full action-bound
//! two-phase flow (export, request -> confirm -> execute) plus the absent-user
//! constant-shape path. One sequential test (it toggles process env to enable
//! erasure with a zero grace window so the sweeper executes immediately).

mod common;

use axum::http::StatusCode;
use base64::Engine;
use k256::schnorr::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use smirk_backend_core::core::crypto::nip98::{descriptor_sha256, request_descriptor};
use smirk_backend_core::models::db::NewUser;

const KIND: u32 = 27235;

fn random_signer() -> SigningKey {
    loop {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        if let Ok(sk) = SigningKey::from_bytes(&b) {
            return sk;
        }
    }
}

/// Build a `Nostr <base64(event)>` signed-action token for an erasure purpose.
fn sign(
    sk: &SigningKey,
    url: &str,
    purpose: &str,
    nonce: &str,
    descriptor_path: &str,
    target: Option<(&str, &str)>,
) -> String {
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let payload = descriptor_sha256(&request_descriptor("POST", descriptor_path, "", b""));
    let mut tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), "POST".to_string()],
        vec!["purpose".to_string(), purpose.to_string()],
        vec!["challenge".to_string(), nonce.to_string()],
        vec!["payload".to_string(), payload],
    ];
    if let Some((k, v)) = target {
        tags.push(vec![k.to_string(), v.to_string()]);
    }
    let created_at = chrono::Utc::now().timestamp();
    let serial =
        serde_json::to_string(&serde_json::json!([0, pk, created_at, KIND, tags, ""])).unwrap();
    let id = hex::encode(Sha256::digest(serial.as_bytes()));
    let sig = sk.sign_raw(&hex::decode(&id).unwrap(), &[0u8; 32]).unwrap();
    let ev = serde_json::json!({
        "id": id, "pubkey": pk, "created_at": created_at,
        "kind": KIND, "tags": tags, "content": "", "sig": hex::encode(sig.to_bytes())
    });
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&ev).unwrap())
    )
}

#[tokio::test]
async fn erasure_request_confirm_execute_flow() {
    std::env::set_var("ERASURE_ENABLED", "true");
    std::env::set_var(
        "ADMIN_KEY_INTEGRITY_SECRET",
        "erasure-integrity-secret-at-least-32-bytes!",
    );
    std::env::set_var("ERASURE_GRACE_PERIOD_HOURS", "0"); // execute immediately

    let app = require_app!();
    let base = app
        .state
        .config
        .identity
        .public_api_url
        .clone()
        .expect("PUBLIC_API_URL");

    // A user with a linked nostr identity that we control the key for.
    let sk = random_signer();
    let pk = hex::encode(sk.verifying_key().to_bytes());
    app.state
        .db
        .create_user(NewUser {
            username: None,
            pubkey_hash: Some(format!("pk-{}", uuid::Uuid::new_v4())),
            nostr_pubkey: Some(pk.clone()),
            wallet_birthday: None,
            seed_fingerprint: None,
            xmr_start_height: None,
            wow_start_height: None,
        })
        .await
        .unwrap();

    let challenge = |purpose: &'static str| {
        let app = &app;
        async move {
            let (st, body) = app
                .request(
                    "POST",
                    "/api/v1/account/erasure/challenge",
                    None,
                    Some(serde_json::json!({ "purpose": purpose })),
                )
                .await;
            assert_eq!(st, StatusCode::OK, "challenge {purpose}");
            body["challenge"].as_str().unwrap().to_string()
        }
    };

    // Export (see-before-delete): proof-gated, returns no view keys.
    let nonce = challenge("erasure_export").await;
    let token = sign(
        &sk,
        &format!("{base}/account/export"),
        "erasure_export",
        &nonce,
        "/api/v1/account/export",
        None,
    );
    let (st, body) = app
        .request(
            "POST",
            "/api/v1/account/export",
            None,
            Some(serde_json::json!({ "token": token, "nonce": nonce })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "export: {body:?}");
    assert_eq!(body["nostr_pubkey"].as_str().unwrap(), pk);

    // Phase 1: request.
    let nonce = challenge("erasure_request").await;
    let token = sign(
        &sk,
        &format!("{base}/account/erasure"),
        "erasure_request",
        &nonce,
        "/api/v1/account/erasure",
        None,
    );
    let (st, body) = app
        .request(
            "POST",
            "/api/v1/account/erasure",
            None,
            Some(serde_json::json!({ "token": token, "nonce": nonce })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "request: {body:?}");
    let erasure_id = body["erasure_id"].as_str().unwrap().to_string();
    assert_eq!(body["status"], "pending");

    // Phase 2: confirm (bound to the erasure_id).
    let nonce = challenge("erasure_confirm").await;
    let confirm_path = format!("/account/erasure/{erasure_id}/confirm");
    let token = sign(
        &sk,
        &format!("{base}{confirm_path}"),
        "erasure_confirm",
        &nonce,
        &format!("/api/v1{confirm_path}"),
        Some(("erasure_id", &erasure_id)),
    );
    let (st, body) = app
        .request(
            "POST",
            &format!("/api/v1{confirm_path}"),
            None,
            Some(serde_json::json!({ "token": token, "nonce": nonce })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "confirm: {body:?}");
    assert_eq!(body["status"], "confirmed");

    // Execute (grace = 0, so it is due now).
    let n = smirk_backend_core::api::erasure::run_erasure_sweep(&app.state, 50)
        .await
        .unwrap();
    assert!(n >= 1, "at least our request executed");

    // The user is gone.
    assert!(
        app.state
            .db
            .find_user_by_nostr_pubkey(&pk)
            .await
            .unwrap()
            .is_none(),
        "account erased"
    );

    // Absent user: a proof from an unlinked key returns the SAME shape (no oracle).
    let stranger = random_signer();
    let nonce = challenge("erasure_request").await;
    let token = sign(
        &stranger,
        &format!("{base}/account/erasure"),
        "erasure_request",
        &nonce,
        "/api/v1/account/erasure",
        None,
    );
    let (st, body) = app
        .request(
            "POST",
            "/api/v1/account/erasure",
            None,
            Some(serde_json::json!({ "token": token, "nonce": nonce })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "absent-user request is constant-shape");
    assert!(body["erasure_id"].as_str().is_some());
    assert_eq!(body["status"], "pending");

    for k in [
        "ERASURE_ENABLED",
        "ADMIN_KEY_INTEGRITY_SECRET",
        "ERASURE_GRACE_PERIOD_HOURS",
    ] {
        std::env::remove_var(k);
    }
}
