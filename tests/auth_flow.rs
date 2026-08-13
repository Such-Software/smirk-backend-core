//! L1 integration: HTTP flows through the real router against a real database.
//! Exercises routing, the auth gate, session refresh rotation, the username +
//! key endpoints, the NIP-05 directory, and the `/auth/extension` identity rules
//! (seed-fingerprint ownership, and the domain separation that keeps a login
//! signature from doubling as a derivation-rotation proof) end to end.

mod common;

use axum::http::StatusCode;
use base64::Engine;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use rand::rngs::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use smirk_backend_core::models::db::{AssetType, NewUser, NewUserKey};
use uuid::Uuid;

/// A fresh secp256k1 wallet identity: the ECDSA signing key plus its compressed
/// SEC1 public key hex (the exact string the server hashes into `pubkey_hash`).
fn btc_identity() -> (SigningKey, String) {
    let secret = SecretKey::random(&mut OsRng);
    let public = hex::encode(secret.public_key().to_encoded_point(true).as_bytes());
    (SigningKey::from(&secret), public)
}

/// The server's identity handle for a public key: `hex(SHA256(public_key))`.
fn pubkey_hash(public_key: &str) -> String {
    hex::encode(Sha256::digest(public_key.as_bytes()))
}

/// A fresh 64-hex seed fingerprint (the wallet-side format).
fn fresh_fingerprint() -> String {
    hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()))
}

/// BIP-137 base64 signature over the Bitcoin signed-message hash of `message`:
/// 65 bytes, a header byte (which the verifier drops) followed by r||s.
fn sign_bip137(sk: &SigningKey, message: &str) -> String {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
    preimage.push(message.len() as u8); // every message signed here is < 253 bytes
    preimage.extend_from_slice(message.as_bytes());
    let hash = Sha256::digest(Sha256::digest(&preimage));
    let sig: Signature = sk.sign_prehash(&hash[..]).expect("sign prehash");
    let mut out = vec![0x1fu8];
    out.extend_from_slice(&sig.to_bytes()[..]);
    base64::engine::general_purpose::STANDARD.encode(out)
}

/// POST `/auth/extension` with a freshly signed timestamp proof.
async fn extension_login(
    app: &common::TestApp,
    sk: &SigningKey,
    public_key: &str,
    seed_fingerprint: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let ts = chrono::Utc::now().timestamp();
    let body = json!({
        "keys": [{ "asset": "btc", "public_key": public_key }],
        "seed_fingerprint": seed_fingerprint,
        "signed_timestamp": ts,
        "signature": sign_bip137(sk, &format!("smirk-auth-{ts}")),
    });
    app.request("POST", "/api/v1/auth/extension", None, Some(body))
        .await
}

#[tokio::test]
async fn health_is_ok() {
    let app = require_app!();
    let (status, body) = app.request("GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn me_requires_a_token() {
    let app = require_app!();
    let (status, _) = app.request("GET", "/api/v1/auth/me", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_returns_with_a_valid_token() {
    let app = require_app!();
    let (_uid, access, _refresh) = app.mint_session().await;
    let (status, body) = app
        .request("GET", "/api/v1/auth/me", Some(&access), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_object());
}

#[tokio::test]
async fn refresh_rotates_and_revokes_the_old_token() {
    let app = require_app!();
    let (_uid, _access, refresh) = app.mint_session().await;

    let (status, body) = app
        .request(
            "POST",
            "/api/v1/auth/refresh",
            None,
            Some(json!({ "refresh_token": refresh })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());

    // The old refresh token was revoked by the rotation: reuse is rejected.
    let (status2, _) = app
        .request(
            "POST",
            "/api/v1/auth/refresh",
            None,
            Some(json!({ "refresh_token": refresh })),
        )
        .await;
    assert_eq!(status2, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn set_username_then_lookup() {
    let app = require_app!();
    let (_uid, access, _r) = app.mint_session().await;
    // Username rule: 3-32 chars, lowercase [a-z0-9_]; keep the unique suffix short.
    let name = format!("u{}", &Uuid::new_v4().simple().to_string()[..16]);

    let (status, _) = app
        .request(
            "POST",
            "/api/v1/users/me/username",
            Some(&access),
            Some(json!({ "username": name })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (s2, _body) = app
        .request(
            "GET",
            &format!("/api/v1/users/by-username/{name}"),
            None,
            None,
        )
        .await;
    assert_eq!(s2, StatusCode::OK);
}

#[tokio::test]
async fn set_username_requires_auth() {
    let app = require_app!();
    let (status, _) = app
        .request(
            "POST",
            "/api/v1/users/me/username",
            None,
            Some(json!({ "username": "whoever" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_key_then_fetch() {
    let app = require_app!();
    let (uid, access, _r) = app.mint_session().await;

    let (status, _) = app
        .request(
            "POST",
            "/api/v1/keys",
            Some(&access),
            Some(json!({ "asset": "btc", "public_key": "02deadbeef" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (s2, _body) = app
        .request("GET", &format!("/api/v1/users/{uid}/keys"), None, None)
        .await;
    assert_eq!(s2, StatusCode::OK);
}

#[tokio::test]
async fn nip05_unknown_name_is_empty() {
    let app = require_app!();
    let (status, body) = app
        .request(
            "GET",
            "/.well-known/nostr.json?name=does-not-exist-xyz",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let empty = body["names"]
        .as_object()
        .map(|m| m.is_empty())
        .unwrap_or(true);
    assert!(empty, "unknown name must resolve to no entry");
}

#[tokio::test]
async fn returning_login_never_takes_another_rows_seed_fingerprint() {
    // Regression: the fingerprint-ownership check was skipped for a RETURNING
    // user, so a login carrying someone else's fingerprint tried to backfill it,
    // violated the UNIQUE index, and 500d that account on every later login.
    let app = require_app!();

    // Wallet A registers and owns the fingerprint.
    let (sk_a, pk_a) = btc_identity();
    let fp = fresh_fingerprint();
    let (s_a, body_a) = extension_login(&app, &sk_a, &pk_a, Some(&fp)).await;
    assert_eq!(s_a, StatusCode::OK, "body={body_a}");
    let id_a = body_a["user"]["id"].as_str().unwrap().to_string();

    // A signs in again with its OWN fingerprint: same row, no conflict.
    let (s_a2, body_a2) = extension_login(&app, &sk_a, &pk_a, Some(&fp)).await;
    assert_eq!(s_a2, StatusCode::OK, "body={body_a2}");
    assert_eq!(body_a2["user"]["id"].as_str().unwrap(), id_a);
    assert_eq!(body_a2["is_new"], false);

    // Wallet B registers WITHOUT a fingerprint, then returns carrying A's.
    let (sk_b, pk_b) = btc_identity();
    let (s_b, body_b) = extension_login(&app, &sk_b, &pk_b, None).await;
    assert_eq!(s_b, StatusCode::OK, "body={body_b}");
    let id_b = body_b["user"]["id"].as_str().unwrap().to_string();
    assert_ne!(id_a, id_b);

    let (s_b2, body_b2) = extension_login(&app, &sk_b, &pk_b, Some(&fp)).await;
    assert_eq!(
        s_b2,
        StatusCode::OK,
        "a returning login must not 500 on a foreign fingerprint: body={body_b2}"
    );
    assert_eq!(body_b2["user"]["id"].as_str().unwrap(), id_b);

    // A still owns the fingerprint; B never acquired one.
    let owner = app
        .state
        .db
        .get_user_by_seed_fingerprint(&fp)
        .await
        .unwrap()
        .expect("the fingerprint still resolves");
    assert_eq!(owner.id.to_string(), id_a);
    let row_b = app
        .state
        .db
        .get_user(Uuid::parse_str(&id_b).unwrap())
        .await
        .unwrap()
        .expect("B still present");
    assert!(
        row_b.seed_fingerprint.is_none(),
        "B must not have taken another wallet's fingerprint"
    );
}

#[tokio::test]
async fn a_login_signature_is_rejected_as_a_rotation_proof() {
    // SECURITY: the derivation-rotation proof signs a DEDICATED message bound to
    // this instance and to the NEW pubkey_hash, so an ordinary login signature
    // (`smirk-auth-{ts}`) is worthless as one. Without that separation a hostile
    // or compromised instance could capture a victim's login signature and replay
    // it, within the drift window, to re-point the victim's payout keys.
    let app = require_app!();

    // Victim registers, so their BTC key is on file under their fingerprint.
    let (sk_v, pk_v) = btc_identity();
    let fp = fresh_fingerprint();
    let (s_v, body_v) = extension_login(&app, &sk_v, &pk_v, Some(&fp)).await;
    assert_eq!(s_v, StatusCode::OK, "body={body_v}");
    let victim_id = body_v["user"]["id"].as_str().unwrap().to_string();

    // Attacker: their own BTC key, the victim's (non-secret) fingerprint, and a
    // captured victim LOGIN signature presented as the rotation proof.
    let ts = chrono::Utc::now().timestamp();
    let captured_login = sign_bip137(&sk_v, &format!("smirk-auth-{ts}"));
    let (sk_x, pk_x) = btc_identity();
    let (status, out) = app
        .request(
            "POST",
            "/api/v1/auth/extension",
            None,
            Some(json!({
                "keys": [{ "asset": "btc", "public_key": pk_x }],
                "seed_fingerprint": fp,
                "signed_timestamp": ts,
                "signature": sign_bip137(&sk_x, &format!("smirk-auth-{ts}")),
                "rotation_signature": captured_login,
            })),
        )
        .await;

    // The rotation is refused: the caller gets a brand-new identity instead.
    assert_eq!(status, StatusCode::OK, "body={out}");
    assert_ne!(
        out["user"]["id"].as_str().unwrap(),
        victim_id,
        "a login signature must never rotate someone else's account"
    );
    assert_eq!(out["is_new"], true);

    // The victim's row is untouched: same pubkey_hash, same fingerprint.
    let victim = app
        .state
        .db
        .get_user_by_pubkey_hash(&pubkey_hash(&pk_v))
        .await
        .unwrap()
        .expect("victim still resolves by its original pubkey_hash");
    assert_eq!(victim.id.to_string(), victim_id);
    let owner = app
        .state
        .db
        .get_user_by_seed_fingerprint(&fp)
        .await
        .unwrap()
        .expect("the fingerprint still resolves");
    assert_eq!(owner.id.to_string(), victim_id);
}

#[tokio::test]
async fn extension_login_adopts_a_keyless_row_only_for_the_on_file_btc_key() {
    // Regression: `nostr_register` mints its row with pubkey_hash NULL, so the
    // same wallet's first /auth/extension matched nothing by pubkey and minted a
    // SECOND row, stranding the handle, tips and premium state on the first. The
    // adoption is gated on the BTC key ALREADY ON FILE, so a bare fingerprint
    // (which check-restore discloses, and which is therefore not a secret) still
    // cannot claim someone else's account.
    let app = require_app!();
    let db = &app.state.db;

    // Exactly the state an npub-native registration leaves behind: an npub-keyed
    // row with a seed fingerprint and a BTC key, but no pubkey_hash.
    let (sk, pk) = btc_identity();
    let fp = fresh_fingerprint();
    let npub = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
    let keyless = db
        .create_user(NewUser {
            username: None,
            pubkey_hash: None,
            nostr_pubkey: Some(npub.clone()),
            wallet_birthday: None,
            seed_fingerprint: Some(fp.clone()),
            xmr_start_height: None,
            wow_start_height: None,
        })
        .await
        .unwrap();
    let keyless_id = keyless.id.to_string();
    let btc_on_file = NewUserKey {
        user_id: keyless.id,
        asset: AssetType::Btc,
        public_key: pk.clone(),
        public_spend_key: None,
        key_type: "primary".to_string(),
    };
    db.upsert_user_key(btc_on_file).await.unwrap();

    // A DIFFERENT wallet that knows only the fingerprint gets its own identity;
    // the keyless row is left alone.
    let (sk_x, pk_x) = btc_identity();
    let (s_x, body_x) = extension_login(&app, &sk_x, &pk_x, Some(&fp)).await;
    assert_eq!(s_x, StatusCode::OK, "body={body_x}");
    assert_eq!(body_x["is_new"], true);
    assert_ne!(body_x["user"]["id"].as_str().unwrap(), keyless_id);
    let after = db.get_user(keyless.id).await.unwrap();
    assert!(
        after.is_some_and(|u| u.pubkey_hash.is_none()),
        "a bare fingerprint must not claim the keyless row"
    );

    // The real wallet (same seed AND the BTC key on file) adopts that row.
    let (s_ok, body_ok) = extension_login(&app, &sk, &pk, Some(&fp)).await;
    assert_eq!(s_ok, StatusCode::OK, "body={body_ok}");
    assert_eq!(body_ok["is_new"], false);
    assert_eq!(body_ok["user"]["id"].as_str().unwrap(), keyless_id);

    // One identity, not two: the row now answers to the pubkey_hash and keeps
    // the Nostr identity it registered with.
    let adopted = db
        .get_user_by_pubkey_hash(&pubkey_hash(&pk))
        .await
        .unwrap()
        .expect("the pubkey_hash now resolves");
    assert_eq!(adopted.id, keyless.id);
    assert_eq!(adopted.nostr_pubkey.as_deref(), Some(npub.as_str()));
}
