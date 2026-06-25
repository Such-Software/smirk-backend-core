//! L1 integration: the public prices endpoint, both feature-flag states.
//!
//! Drives `FEATURE_PRICES` explicitly and rebuilds the app for each state, so
//! both paths are deterministic without any network call. (The background
//! refresh task lives in `main`, not `build_router`, so under the harness the
//! enabled feed simply serves an empty, not-yet-populated snapshot.) The live
//! upstream fetch is covered by `infra::prices` unit tests and is an L3 concern.

mod common;

use axum::http::StatusCode;

#[tokio::test]
async fn prices_endpoint_respects_the_feature_flag() {
    // Disabled → 404, so a client reading /capabilities never special-cases it.
    std::env::set_var("FEATURE_PRICES", "false");
    let Some(app) = common::try_app().await else {
        return;
    };
    let (status, body) = app.request("GET", "/api/v1/prices", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "NOT_FOUND");

    // Enabled, before any refresh → 200 with the documented empty shape (the
    // background task lives in `main`, not the harness, so updated_at is null).
    std::env::set_var("FEATURE_PRICES", "true");
    let app = common::try_app()
        .await
        .expect("app builds with prices enabled");
    let (status, body) = app.request("GET", "/api/v1/prices", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["currency"].as_str().is_some(), "currency present");
    assert!(body["prices"].is_object(), "prices is a map");
    assert!(body["updated_at"].is_null(), "not yet refreshed");

    // Enabled, with a populated snapshot → the handler serves the quotes and a
    // non-null RFC 3339 timestamp. Drives the serving path the inert
    // PRICES_ASSETS env-var never could; feed *selection* is unit-tested in
    // infra::prices.
    {
        let mut snap = app.state.prices.write().await;
        snap.prices.insert("btc".into(), 64000.0);
        snap.prices.insert("xmr".into(), 150.0);
        snap.updated_at = Some(chrono::Utc::now());
    }
    let (status, body) = app.request("GET", "/api/v1/prices", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["prices"]["btc"], 64000.0);
    assert_eq!(body["prices"]["xmr"], 150.0);
    assert!(
        body["updated_at"].as_str().is_some(),
        "timestamp serialized"
    );

    std::env::remove_var("FEATURE_PRICES");
}
