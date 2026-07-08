//! CORS policy per route group. The NIP-05 well-known directory is public data that
//! MUST be cross-origin fetchable for federation; the authenticated API honors the
//! operator's `CORS_ALLOWED_ORIGINS`. Regression guard for the per-route CORS split
//! in `build_router` (a single global layer used to let a restrictive API policy
//! silently break NIP-05 resolution).

mod common;

use axum::http::StatusCode;

fn acao(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

#[tokio::test]
async fn nip05_well_known_is_cross_origin_even_when_api_cors_restricted() {
    // Operator restricts the API to their own frontend only.
    let app = match common::try_app_with(|cfg| {
        cfg.cors_allowed_origins = vec!["https://app.smirk.cash".to_string()];
    })
    .await
    {
        Some(a) => a,
        None => {
            eprintln!("skipping: TEST_DATABASE_URL not set");
            return;
        }
    };

    // The well-known, fetched from a FOREIGN origin (a Goblin domain), must be `*`.
    let (status, headers, _body) = app
        .request_full(
            "GET",
            "/.well-known/nostr.json?name=whoever",
            &[("origin", "https://goblin.st")],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        acao(&headers).as_deref(),
        Some("*"),
        "NIP-05 directory must serve ACAO: * so any domain can resolve names (federation)"
    );

    // The restricted API, from that same foreign origin, must NOT get `*` — proving
    // the two CORS policies are genuinely distinct (not both permissive).
    let (_s, api_headers, _b) = app
        .request_full(
            "GET",
            "/api/v1/capabilities",
            &[("origin", "https://goblin.st")],
            None,
        )
        .await;
    assert_ne!(
        acao(&api_headers).as_deref(),
        Some("*"),
        "the API must honor the operator's restricted CORS, not fall back to *"
    );
}
