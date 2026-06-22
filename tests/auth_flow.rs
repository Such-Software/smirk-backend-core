//! L1 integration: HTTP flows through the real router against a real database.
//! Exercises routing, the auth gate, session refresh rotation, the username +
//! key endpoints, and the NIP-05 directory end to end.

mod common;

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

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
