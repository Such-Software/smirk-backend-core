//! L1 integration: npub-native registration (`POST /auth/nostr/register`) — the
//! create-by-npub path (no BTC signature) and the `seed_fingerprint` MERGE dedup
//! that must never split one wallet into two identities. Skips without
//! `TEST_DATABASE_URL` (see `common`).

mod common;

use axum::http::StatusCode;
use base64::Engine;
use k256::schnorr::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use smirk_backend_core::core::crypto::nip98::{descriptor_sha256, request_descriptor};

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

/// Build the `Nostr <base64(event)>` register signed-action (empty-body
/// descriptor contract, purpose `nostr_register`).
fn sign_register(sk: &SigningKey, url: &str, nonce: &str) -> String {
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let payload = descriptor_sha256(&request_descriptor(
        "POST",
        "/api/v1/auth/nostr/register",
        "",
        b"",
    ));
    let tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), "POST".to_string()],
        vec!["purpose".to_string(), "nostr_register".to_string()],
        vec!["challenge".to_string(), nonce.to_string()],
        vec!["payload".to_string(), payload],
    ];
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

/// Full register round-trip: fetch a nonce, sign it, POST the register body.
async fn register(
    app: &common::TestApp,
    sk: &SigningKey,
    base: &str,
    seed_fingerprint: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let (_s, chal) = app
        .request("GET", "/api/v1/auth/nostr/register-challenge", None, None)
        .await;
    let nonce = chal["nonce"].as_str().unwrap().to_string();
    let url = format!("{}/auth/nostr/register", base);
    let token = sign_register(sk, &url, &nonce);
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let body = serde_json::json!({
        "nostr_token": token,
        "nonce": nonce,
        "keys": [{ "asset": "btc", "public_key": format!("btcpub-{}", &pk[..16]) }],
        "seed_fingerprint": seed_fingerprint,
    });
    app.request("POST", "/api/v1/auth/nostr/register", None, Some(body))
        .await
}

#[tokio::test]
async fn register_creates_user_by_npub_and_is_idempotent() {
    let app = require_app!();
    let base = app
        .state
        .config
        .identity
        .public_api_url
        .clone()
        .expect("PUBLIC_API_URL");
    let sk = random_signer();
    let pk = hex::encode(sk.verifying_key().to_bytes());

    // First register mints a user keyed by the npub — no BTC signature.
    let (status, body) = register(&app, &sk, &base, None).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["is_new"], true);
    assert!(body["access_token"].as_str().is_some());
    assert!(app
        .state
        .db
        .find_user_by_nostr_pubkey(&pk)
        .await
        .unwrap()
        .is_some());

    // Re-register with the same npub resolves the same user (is_new=false).
    let (s2, b2) = register(&app, &sk, &base, None).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b2["is_new"], false);
}

#[tokio::test]
async fn register_replays_are_rejected() {
    let app = require_app!();
    let base = app
        .state
        .config
        .identity
        .public_api_url
        .clone()
        .expect("PUBLIC_API_URL");
    let sk = random_signer();
    let (_s, chal) = app
        .request("GET", "/api/v1/auth/nostr/register-challenge", None, None)
        .await;
    let nonce = chal["nonce"].as_str().unwrap().to_string();
    let url = format!("{}/auth/nostr/register", base);
    let token = sign_register(&sk, &url, &nonce);
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let body = serde_json::json!({
        "nostr_token": token, "nonce": nonce,
        "keys": [{ "asset": "btc", "public_key": format!("btcpub-{}", &pk[..16]) }],
    });
    let (s1, _) = app
        .request("POST", "/api/v1/auth/nostr/register", None, Some(body.clone()))
        .await;
    assert_eq!(s1, StatusCode::OK);
    // Same nonce again -> consumed -> rejected (single-use replay guard).
    let (s2, _) = app
        .request("POST", "/api/v1/auth/nostr/register", None, Some(body))
        .await;
    assert_ne!(s2, StatusCode::OK, "a consumed nonce must not register again");
}

#[tokio::test]
async fn register_merges_onto_existing_seed_fingerprint_row() {
    let app = require_app!();
    let base = app
        .state
        .config
        .identity
        .public_api_url
        .clone()
        .expect("PUBLIC_API_URL");

    // A pre-existing BTC-anchored row carrying a seed_fingerprint (no npub yet).
    let fp = format!("fp-{}", uuid::Uuid::new_v4());
    let existing = app
        .state
        .db
        .get_or_create_user_by_pubkey_hash(
            &format!("pkh-{}", uuid::Uuid::new_v4()),
            None,
            None,
            Some(fp.clone()),
            None,
            None,
        )
        .await
        .unwrap();
    assert!(existing.nostr_pubkey.is_none());

    // Register npub-native with the SAME seed -> MERGE onto that row, not a new one.
    let sk = random_signer();
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let (status, body) = register(&app, &sk, &base, Some(&fp)).await;
    assert_eq!(status, StatusCode::OK, "body={body}");

    let merged = app
        .state
        .db
        .find_user_by_nostr_pubkey(&pk)
        .await
        .unwrap()
        .expect("npub resolves after register");
    assert_eq!(
        merged.id, existing.id,
        "npub register must MERGE onto the existing seed_fingerprint row, not split identity"
    );
}
