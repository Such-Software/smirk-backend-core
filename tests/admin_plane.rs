//! L1 integration: admin-plane posture (operator §2.1/§2.2) — Host allowlist
//! (anti DNS-rebinding) + anti-clickjacking headers. Uses a raw oneshot so it can
//! set the Host header and read response headers.

mod common;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use std::net::SocketAddr;
use tower::ServiceExt;

fn admin_req(host: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/admin/me")
        .header("host", host)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn host_allowlist_and_anti_clickjacking() {
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

    let Some(app) = common::try_app().await else {
        return;
    };
    let admin = app.admin_router();

    // A foreign Host (DNS-rebinding) is rejected before auth even runs.
    let resp = admin
        .clone()
        .oneshot(admin_req("evil.example"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "rebinding host rejected"
    );

    // A loopback Host reaches the guard (401 unauthenticated, not 403) and the
    // response carries the anti-clickjacking headers.
    let resp = admin.oneshot(admin_req("127.0.0.1:8081")).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "loopback host accepted"
    );
    assert_eq!(
        resp.headers().get("x-frame-options").map(|v| v.as_bytes()),
        Some(b"DENY".as_ref())
    );
    assert_eq!(
        resp.headers()
            .get("content-security-policy")
            .map(|v| v.as_bytes()),
        Some(b"frame-ancestors 'none'".as_ref())
    );

    for k in [
        "ADMIN_ENABLED",
        "ADMIN_JWT_SECRET",
        "ADMIN_KEY_INTEGRITY_SECRET",
        "ADMIN_PUBLIC_URL",
    ] {
        std::env::remove_var(k);
    }
}
