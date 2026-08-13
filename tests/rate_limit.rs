//! L1 integration: the per-IP rate limiter actually throttles a burst, and it
//! keys on the client IP the trusted-proxy policy resolves.
//!
//! The strict tier wraps the unauthenticated auth/website surface. The governor
//! runs before the handler, so an unauthenticated burst to a strict-tier route
//! still counts — past the burst size it must return 429. (All requests share the
//! injected loopback peer, so they hit one bucket.)

mod common;

use axum::http::StatusCode;
use ipnetwork::IpNetwork;
use std::net::IpAddr;

#[tokio::test]
async fn strict_tier_throttles_a_burst() {
    let app = require_app!();
    let mut saw_429 = false;
    for _ in 0..40 {
        let (status, _) = app.request("GET", "/api/v1/auth/me", None, None).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(
        saw_429,
        "a rapid burst to a strict-tier endpoint should be rate-limited (429)"
    );
}

#[tokio::test]
async fn spoofed_forwarded_for_from_an_untrusted_peer_shares_one_bucket() {
    let app = require_app!();
    // Default config trusts no proxies, so the loopback peer the harness injects
    // is untrusted and its X-Forwarded-For must be ignored. If the limiter keyed
    // on the header, every request below would mint a fresh bucket and nothing
    // would ever throttle.
    let mut saw_429 = false;
    for i in 0..40 {
        let spoofed = format!("203.0.113.{i}");
        let (status, _, _) = app
            .request_full(
                "GET",
                "/api/v1/auth/me",
                &[("x-forwarded-for", spoofed.as_str())],
                None,
            )
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            break;
        }
    }
    assert!(
        saw_429,
        "a spoofed X-Forwarded-For from an untrusted peer must not buy its own bucket"
    );
}

#[tokio::test]
async fn trusted_proxy_gets_a_bucket_per_forwarded_client() {
    // With the peer inside `trusted_proxies`, X-Forwarded-For IS the client, so
    // distinct clients behind the proxy must not share (and exhaust) one bucket:
    // that is the whole point of keying on the resolved client IP.
    let maybe_app = common::try_app_with(|cfg| {
        cfg.trusted_proxies = vec![IpNetwork::from(IpAddr::from([127, 0, 0, 1]))];
    })
    .await;
    let Some(app) = maybe_app else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };

    for i in 0..40 {
        let client = format!("198.51.100.{i}");
        let (status, _, _) = app
            .request_full(
                "GET",
                "/api/v1/auth/me",
                &[("x-forwarded-for", client.as_str())],
                None,
            )
            .await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "one request per forwarded client must not trip the limiter ({client})"
        );
    }
}
