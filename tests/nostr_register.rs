//! L1 integration: npub-native registration (`POST /auth/nostr/register`) — the
//! create-by-npub path (no BTC signature) and the `seed_fingerprint` handling.
//! A fingerprint match onto a pre-existing row is REFUSED: the endpoint
//! proves only npub control, so it must not bind an npub onto an account keyed by
//! another (on-file) credential without proof. The reverse direction is here too:
//! the same wallet arriving at `/auth/extension` afterwards ADOPTS its npub-native
//! row (it proves control of the BTC key already on file) instead of splitting the
//! identity in two. Skips without `TEST_DATABASE_URL` (see `common`).

mod common;

use axum::http::StatusCode;
use base64::Engine;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey as EcdsaSigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::SigningKey;
use k256::SecretKey;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use smirk_backend_core::core::crypto::nip98::{descriptor_sha256, request_descriptor};

const KIND: u32 = 27235;

/// A fresh secp256k1 wallet identity: the ECDSA signing key plus its compressed
/// SEC1 public key hex (the exact string the server hashes into `pubkey_hash`).
fn btc_identity() -> (EcdsaSigningKey, String) {
    let secret = SecretKey::random(&mut OsRng);
    let public = hex::encode(secret.public_key().to_encoded_point(true).as_bytes());
    (EcdsaSigningKey::from(&secret), public)
}

/// BIP-137 base64 signature over the Bitcoin signed-message hash of `message`:
/// 65 bytes, a header byte (which the verifier drops) followed by r||s.
fn sign_bip137(sk: &EcdsaSigningKey, message: &str) -> String {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
    preimage.push(message.len() as u8); // every message signed here is < 253 bytes
    preimage.extend_from_slice(message.as_bytes());
    let hash = Sha256::digest(Sha256::digest(&preimage));
    let sig: EcdsaSignature = sk.sign_prehash(&hash[..]).expect("sign prehash");
    let mut out = vec![0x1fu8];
    out.extend_from_slice(&sig.to_bytes()[..]);
    base64::engine::general_purpose::STANDARD.encode(out)
}

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
    let pk = hex::encode(sk.verifying_key().to_bytes());
    register_with_btc(
        app,
        sk,
        base,
        seed_fingerprint,
        &format!("btcpub-{}", &pk[..16]),
    )
    .await
}

/// Like [`register`], but with an explicit BTC public key: the adoption test
/// needs a REAL secp256k1 key it can sign `/auth/extension` with afterwards.
async fn register_with_btc(
    app: &common::TestApp,
    sk: &SigningKey,
    base: &str,
    seed_fingerprint: Option<&str>,
    btc_public_key: &str,
) -> (StatusCode, serde_json::Value) {
    let (_s, chal) = app
        .request("GET", "/api/v1/auth/nostr/register-challenge", None, None)
        .await;
    let nonce = chal["nonce"].as_str().unwrap().to_string();
    let url = format!("{}/auth/nostr/register", base);
    let token = sign_register(sk, &url, &nonce);
    let body = serde_json::json!({
        "nostr_token": token,
        "nonce": nonce,
        "keys": [{ "asset": "btc", "public_key": btc_public_key }],
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
        .cfg()
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
        .cfg()
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
        .request(
            "POST",
            "/api/v1/auth/nostr/register",
            None,
            Some(body.clone()),
        )
        .await;
    assert_eq!(s1, StatusCode::OK);
    // Same nonce again -> consumed -> rejected (single-use replay guard).
    let (s2, _) = app
        .request("POST", "/api/v1/auth/nostr/register", None, Some(body))
        .await;
    assert_ne!(
        s2,
        StatusCode::OK,
        "a consumed nonce must not register again"
    );
}

#[tokio::test]
async fn register_refuses_to_bind_npub_onto_existing_seed_fingerprint_row_without_proof() {
    // SECURITY: the npub-native register endpoint proves control of the NEW
    // npub only, never of the key ALREADY ON FILE. seed_fingerprint is a lookup
    // handle the client sends unauthenticated (check-restore / register), not a
    // credential — so binding an npub onto a pre-existing BTC-anchored row on a
    // fingerprint MATCH alone would let anyone who learns a victim's fingerprint
    // take over that account. The endpoint must fail closed (409); the wallet
    // links its npub through the authenticated POST /auth/nostr/link flow instead.
    let app = require_app!();
    let base = app
        .state
        .cfg()
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

    // Register npub-native with the SAME seed -> REJECTED (no unauthenticated merge).
    let sk = random_signer();
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let (status, body) = register(&app, &sk, &base, Some(&fp)).await;
    assert_eq!(status, StatusCode::CONFLICT, "body={body}");

    // The existing row is left UNTOUCHED and the npub binds to nothing.
    assert!(
        app.state
            .db
            .find_user_by_nostr_pubkey(&pk)
            .await
            .unwrap()
            .is_none(),
        "a rejected register must not bind the npub to any account"
    );
    let after = app
        .state
        .db
        .get_user(existing.id)
        .await
        .unwrap()
        .expect("existing row still present");
    assert!(
        after.nostr_pubkey.is_none(),
        "the victim's row must not have gained an npub"
    );
}

#[tokio::test]
async fn extension_login_adopts_the_npub_native_row_instead_of_splitting_it() {
    // Regression: `nostr_register` mints its row with pubkey_hash NULL, so the
    // SAME wallet's first /auth/extension matched nothing by pubkey and minted a
    // SECOND row, stranding the handle, tips and premium state on the first.
    // Same seed AND the BTC key already on file (whose control the extension
    // request proves): one wallet, so the row adopts the pubkey_hash.
    let app = require_app!();
    let base = app
        .state
        .cfg()
        .identity
        .public_api_url
        .clone()
        .expect("PUBLIC_API_URL");

    let sk = random_signer();
    let npub = hex::encode(sk.verifying_key().to_bytes());
    let (btc_sk, btc_pk) = btc_identity();
    let fp = hex::encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));

    // npub-native registration: the row carries the BTC key but no pubkey_hash.
    let (status, body) = register_with_btc(&app, &sk, &base, Some(&fp), &btc_pk).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    let user_id = body["user"]["id"].as_str().unwrap().to_string();
    let row = app
        .state
        .db
        .find_user_by_nostr_pubkey(&npub)
        .await
        .unwrap()
        .expect("npub row");
    assert!(
        row.pubkey_hash.is_none(),
        "an npub-native row starts without a pubkey_hash"
    );

    // The same wallet now signs in through the extension path.
    let ts = chrono::Utc::now().timestamp();
    let (s2, b2) = app
        .request(
            "POST",
            "/api/v1/auth/extension",
            None,
            Some(serde_json::json!({
                "keys": [{ "asset": "btc", "public_key": btc_pk }],
                "seed_fingerprint": fp,
                "signed_timestamp": ts,
                "signature": sign_bip137(&btc_sk, &format!("smirk-auth-{ts}")),
            })),
        )
        .await;
    assert_eq!(s2, StatusCode::OK, "body={b2}");
    assert_eq!(b2["is_new"], false, "this wallet already had an account");
    assert_eq!(
        b2["user"]["id"].as_str().unwrap(),
        user_id,
        "the extension login must resolve to the SAME user row"
    );

    // One identity, not two: the row now answers to the pubkey_hash as well, and
    // it kept its Nostr identity.
    let pkh = hex::encode(Sha256::digest(btc_pk.as_bytes()));
    let by_pubkey = app
        .state
        .db
        .get_user_by_pubkey_hash(&pkh)
        .await
        .unwrap()
        .expect("the pubkey_hash now resolves");
    assert_eq!(by_pubkey.id.to_string(), user_id);
    assert_eq!(
        by_pubkey.nostr_pubkey.as_deref(),
        Some(npub.as_str()),
        "the adopted row keeps its Nostr identity"
    );
}
