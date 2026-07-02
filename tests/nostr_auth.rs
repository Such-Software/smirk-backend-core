//! L1 integration: Nostr identity LINK flow (Identity Phase 1).
//!
//! Exercises the now-wired link-nonce path end to end at the HTTP layer:
//! `GET /auth/nostr/link-challenge` (authenticated) issues a single-use nonce
//! bound to the caller, and `POST /auth/nostr/link` atomically consumes it +
//! verifies the signed-action proof, storing the npub so a later `nostr_login`
//! resolves to the same wallet. Also pins the cross-impl descriptor contract and
//! covers replay + wrong-user nonce rejection.
//!
//! The `nostr_login` HTTP leg itself (NIP-98 verify → resolve → session) is left
//! to the Playwright suite (it needs a `Nostr <base64>` Authorization header the
//! JSON harness doesn't set); here we assert the linkage it depends on directly.

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

/// Build a `Nostr <base64(event)>` signed-action token binding the nonce +
/// purpose + the empty-body request descriptor (the cross-impl contract).
fn sign(sk: &SigningKey, url: &str, purpose: &str, nonce: &str, descriptor_path: &str) -> String {
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let payload = descriptor_sha256(&request_descriptor("POST", descriptor_path, "", b""));
    let tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), "POST".to_string()],
        vec!["purpose".to_string(), purpose.to_string()],
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

/// The exact descriptor hash the wallet MUST bind as the signed action's
/// `payload` for `POST /auth/nostr/link` — empty body, no query. Pinned here so
/// the binding cannot silently drift; the client's linkNostr test pins the same
/// literal. (KAT — no DB needed.)
#[test]
fn nostr_link_descriptor_sha256_is_pinned() {
    let d = request_descriptor("POST", "/api/v1/auth/nostr/link", "", b"");
    assert_eq!(descriptor_sha256(&d), NOSTR_LINK_DESCRIPTOR_SHA256);
}

const NOSTR_LINK_DESCRIPTOR_SHA256: &str =
    "8d6aaf2ed65252d1be6090415915736c40d775b9f12ade15c3af71bc02cdcc49";

#[tokio::test]
async fn link_challenge_then_link_resolves_and_rejects_replay_and_wrong_user() {
    let app = require_app!();
    let base = app
        .state
        .config
        .identity
        .public_api_url
        .clone()
        .expect("PUBLIC_API_URL");
    let link_url = format!("{base}/auth/nostr/link");

    // ── Happy path: an authenticated user links an npub it controls. ──────────
    let (user_id, access, _refresh) = app.mint_session().await;
    let (st, body) = app
        .request(
            "GET",
            "/api/v1/auth/nostr/link-challenge",
            Some(&access),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "issue link nonce");
    let nonce = body["nonce"].as_str().expect("nonce").to_string();

    let sk = random_signer();
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let token = sign(
        &sk,
        &link_url,
        "nostr_link",
        &nonce,
        "/api/v1/auth/nostr/link",
    );
    let (st, body) = app
        .request(
            "POST",
            "/api/v1/auth/nostr/link",
            Some(&access),
            Some(serde_json::json!({ "nostr_token": token, "nonce": nonce })),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "link accepted: {body:?}");
    assert_eq!(body["nostr_pubkey"].as_str(), Some(pk.as_str()));

    // The linkage nostr_login depends on now resolves to this exact user.
    let resolved = app.state.db.find_user_by_nostr_pubkey(&pk).await.unwrap();
    assert_eq!(resolved.map(|u| u.id), Some(user_id), "login would resolve");

    // ── Replay: the nonce was single-use; reusing it is rejected. ─────────────
    let (st, _) = app
        .request(
            "POST",
            "/api/v1/auth/nostr/link",
            Some(&access),
            Some(serde_json::json!({ "nostr_token": token, "nonce": nonce })),
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "replayed nonce rejected");

    // ── Wrong user: a nonce issued to user B cannot be spent by user A. ───────
    let (_uid_b, access_b, _r) = app.mint_session().await;
    let (st, body) = app
        .request(
            "GET",
            "/api/v1/auth/nostr/link-challenge",
            Some(&access_b),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let nonce_b = body["nonce"].as_str().unwrap().to_string();
    // User A (access) attempts to consume user B's nonce.
    let sk2 = random_signer();
    let token2 = sign(
        &sk2,
        &link_url,
        "nostr_link",
        &nonce_b,
        "/api/v1/auth/nostr/link",
    );
    let (st, _) = app
        .request(
            "POST",
            "/api/v1/auth/nostr/link",
            Some(&access),
            Some(serde_json::json!({ "nostr_token": token2, "nonce": nonce_b })),
        )
        .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "nonce bound to a different user is rejected"
    );
}
