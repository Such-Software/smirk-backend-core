//! L1 integration: the per-IP rate limiter actually throttles a burst.
//!
//! The strict tier wraps the unauthenticated auth/website surface. The governor
//! runs before the handler, so an unauthenticated burst to a strict-tier route
//! still counts — past the burst size it must return 429. (All requests share the
//! injected loopback peer, so they hit one bucket.)

mod common;

use axum::http::StatusCode;

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
