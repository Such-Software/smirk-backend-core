//! L1 integration: website ("Sign in with your wallet") auth, end to end.
//!
//! The regression these pin is the 2026-09-13 report: a user whose wallet
//! worked, whose handle resolved and who was signed in on desktop was told to
//! register, because `website_verify` resolved the signer ONLY through
//! `users.pubkey_hash`. That column holds the BTC key's hash and nothing else,
//! so a signature from LTC/XMR/WOW/Grin matched no row for anyone, and an
//! unregistered key is indistinguishable from an unknown user.
//!
//! Key material here is built in exactly the representation the wallet
//! registers and later signs with (`@smirk/core` `buildKeysList` and the
//! extension's dapp signers): compressed SEC1 hex signed BIP-137 for BTC/LTC,
//! 32-byte Ed25519 hex for XMR/WOW/Grin.

mod common;

use axum::http::StatusCode;
use base64::Engine;
use ed25519_dalek::Signer as _;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use k256::SecretKey;
use rand::rngs::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use smirk_backend_core::models::db::NewUser;
use uuid::Uuid;

/// A wallet's key for one asset, able to produce the two things the sign-in
/// wire carries: the public key as registered, and a signature over a message.
enum AssetKey {
    /// secp256k1 (BTC, LTC): BIP-137 base64 over the Bitcoin signed-message hash.
    Secp(SigningKey),
    /// Ed25519 (XMR, WOW, Grin): 64-byte hex over the raw message bytes.
    Ed(ed25519_dalek::SigningKey),
}

impl AssetKey {
    /// The exact string registered as this asset's `public_key`.
    fn public_key(&self) -> String {
        match self {
            AssetKey::Secp(sk) => hex::encode(sk.verifying_key().to_encoded_point(true).as_bytes()),
            AssetKey::Ed(sk) => hex::encode(sk.verifying_key().to_bytes()),
        }
    }

    /// Sign `message` the way this asset's wallet path signs it.
    fn sign(&self, message: &str) -> String {
        match self {
            AssetKey::Secp(sk) => {
                let mut preimage = Vec::new();
                preimage.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
                // Every message signed in these tests is < 253 bytes.
                preimage.push(message.len() as u8);
                preimage.extend_from_slice(message.as_bytes());
                let hash = Sha256::digest(Sha256::digest(&preimage));
                let sig: Signature = sk.sign_prehash(&hash[..]).expect("sign prehash");
                let mut out = vec![0x1fu8];
                out.extend_from_slice(&sig.to_bytes()[..]);
                base64::engine::general_purpose::STANDARD.encode(out)
            }
            AssetKey::Ed(sk) => hex::encode(sk.sign(message.as_bytes()).to_bytes()),
        }
    }
}

fn secp_key() -> AssetKey {
    AssetKey::Secp(SigningKey::from(&SecretKey::random(&mut OsRng)))
}

/// A fresh Ed25519 key. Seeded from a v4 UUID rather than `SigningKey::generate`
/// so the test does not depend on the crate's optional `rand_core` feature.
fn ed_key() -> AssetKey {
    let seed: [u8; 32] = Sha256::digest(Uuid::new_v4().as_bytes()).into();
    AssetKey::Ed(ed25519_dalek::SigningKey::from_bytes(&seed))
}

/// The server's identity handle for a public key: `hex(SHA256(public_key))`.
fn pubkey_hash(public_key: &str) -> String {
    hex::encode(Sha256::digest(public_key.as_bytes()))
}

/// The coins a wallet onboards with, each with its own fresh key, in the order
/// `buildKeysList` sends them (BTC first: it is the identity).
fn fresh_wallet() -> Vec<(&'static str, AssetKey)> {
    vec![
        ("btc", secp_key()),
        ("ltc", secp_key()),
        ("xmr", ed_key()),
        ("wow", ed_key()),
        ("grin", ed_key()),
    ]
}

fn key_for<'a>(wallet: &'a [(&'static str, AssetKey)], asset: &str) -> &'a AssetKey {
    &wallet
        .iter()
        .find(|(a, _)| *a == asset)
        .expect("wallet holds the asset")
        .1
}

/// Complete onboarding: `POST /auth/extension` with every key in `wallet`,
/// proving control of the BTC key with a freshly signed timestamp.
async fn onboard(
    app: &common::TestApp,
    wallet: &[(&'static str, AssetKey)],
) -> (StatusCode, serde_json::Value) {
    let ts = chrono::Utc::now().timestamp();
    let keys: Vec<_> = wallet
        .iter()
        .map(|(asset, key)| json!({ "asset": asset, "public_key": key.public_key() }))
        .collect();
    let body = json!({
        "keys": keys,
        "signed_timestamp": ts,
        "signature": key_for(wallet, "btc").sign(&format!("smirk-auth-{ts}")),
    });
    app.request("POST", "/api/v1/auth/extension", None, Some(body))
        .await
}

/// The full website handshake for one coin: request a challenge, sign it with
/// that coin's key, and present the proof.
async fn website_sign_in(
    app: &common::TestApp,
    asset: &str,
    key: &AssetKey,
) -> (StatusCode, serde_json::Value) {
    let (status, challenge) = app
        .request(
            "POST",
            "/api/v1/auth/website/challenge",
            None,
            Some(json!({ "origin": "https://smirk.cash" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "challenge must issue");

    let message = challenge["challenge"].as_str().expect("challenge message");
    let body = json!({
        "challenge_id": challenge["challenge_id"],
        "signature": {
            "asset": asset,
            "signature": key.sign(message),
            "public_key": key.public_key(),
        },
    });
    app.request("POST", "/api/v1/auth/website/verify", None, Some(body))
        .await
}

/// THE property: a wallet that finished onboarding can sign in to the website
/// with each coin it registered, and every coin resolves the SAME identity.
///
/// Driven by the set the wallet actually registered, so supporting one more (or
/// one fewer) coin changes the coverage without anyone editing this assertion.
#[tokio::test]
async fn onboarded_wallet_signs_in_with_every_coin_it_registered() {
    let app = require_app!();
    let wallet = fresh_wallet();

    let (status, registered) = onboard(&app, &wallet).await;
    assert_eq!(status, StatusCode::OK, "onboarding must succeed");
    let user_id = registered["user"]["id"]
        .as_str()
        .expect("registration returns the user")
        .to_string();

    for (asset, key) in &wallet {
        let (status, body) = website_sign_in(&app, asset, key).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{asset}: a registered coin must sign in, got {body}"
        );
        assert!(
            body["access_token"].as_str().is_some_and(|t| !t.is_empty()),
            "{asset}: sign-in must issue a session"
        );
        assert_eq!(
            body["user"]["id"].as_str(),
            Some(user_id.as_str()),
            "{asset}: must resolve the wallet that registered the key"
        );
        assert_eq!(
            body["is_new"], false,
            "{asset}: website sign-in must never mint an identity"
        );
    }
}

/// An identity that exists with NO `user_keys` rows still signs in with BTC.
///
/// This is the shape `smirk-admin migrate-legacy` leaves behind: it imports
/// identity (including `pubkey_hash`) and lets the v0.3 client re-register keys
/// on first unlock. Resolving by asset key alone would lock every one of those
/// users out, so the BTC `pubkey_hash` fallback is load-bearing, not legacy
/// residue.
#[tokio::test]
async fn an_imported_identity_without_keys_still_signs_in_with_btc() {
    let app = require_app!();
    let btc = secp_key();

    app.state
        .db
        .create_user(NewUser {
            username: None,
            pubkey_hash: Some(pubkey_hash(&btc.public_key())),
            nostr_pubkey: None,
            wallet_birthday: None,
            seed_fingerprint: None,
            xmr_start_height: None,
            wow_start_height: None,
        })
        .await
        .expect("create imported identity");

    let (status, body) = website_sign_in(&app, "btc", &btc).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an imported identity must not be locked out, got {body}"
    );
}

/// No enumeration: a key that cannot be resolved is refused the same way
/// whether or not an account exists behind it.
///
/// Compares the refusal for a coin key held by a wallet the server has never
/// seen against the refusal for a coin the registered wallet chose not to
/// register. Those are the two cases a prober would use to test for an account,
/// and they must be indistinguishable in both status and body.
#[tokio::test]
async fn an_unresolvable_key_is_refused_identically_whether_or_not_the_account_exists() {
    let app = require_app!();

    // A wallet that onboarded with BTC only, so its LTC key is genuinely
    // unregistered while the account behind it very much exists.
    let partial = vec![("btc", secp_key()), ("ltc", secp_key())];
    let (status, _) = onboard(&app, &partial[..1]).await;
    assert_eq!(status, StatusCode::OK, "partial onboarding must succeed");

    let (known_account, known_body) = website_sign_in(&app, "ltc", key_for(&partial, "ltc")).await;

    // A wallet the server has never seen at all.
    let stranger = fresh_wallet();
    let (no_account, no_account_body) =
        website_sign_in(&app, "ltc", key_for(&stranger, "ltc")).await;

    assert_eq!(
        known_account,
        StatusCode::UNAUTHORIZED,
        "an unregistered coin key must be refused"
    );
    assert_eq!(
        known_account, no_account,
        "refusal status must not disclose whether the account exists"
    );
    assert_eq!(
        known_body["error"], no_account_body["error"],
        "refusal message must not disclose whether the account exists"
    );
}
