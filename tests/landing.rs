//! L1 integration: the public landing surface (operator §2.3). Default-OFF; when
//! on, the default projection is the minimal `{ software.name, status }` and `/`
//! serves HTML.
//!
//! `landing_off_then_on_minimal` toggles process env and must stay the only test
//! here that does; the stats tests drive config directly via `try_app_with` so
//! they cannot race it.

mod common;

use axum::http::StatusCode;

#[tokio::test]
async fn landing_off_then_on_minimal() {
    // Off (default): both the read model and `/` are 404 (no admin-plane hint).
    std::env::remove_var("PUBLIC_LANDING_ENABLED");
    let Some(app) = common::try_app().await else {
        return;
    };
    let (st, _) = app.request("GET", "/api/v1/server-info", None, None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = app.request("GET", "/", None, None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // On, default toggles: minimal projection — only software.name + status.
    std::env::set_var("PUBLIC_LANDING_ENABLED", "true");
    let app = common::try_app().await.expect("app");
    let (st, body) = app.request("GET", "/api/v1/server-info", None, None).await;
    assert_eq!(st, StatusCode::OK);
    let obj = body.as_object().expect("object");
    assert_eq!(obj.len(), 2, "only software + status by default: {body}");
    assert_eq!(body["software"]["name"], "smirk-backend-core");
    assert_eq!(body["status"], "ok");
    assert!(
        body["software"]
            .as_object()
            .unwrap()
            .get("version")
            .is_none(),
        "version omitted by default"
    );
    for hidden in ["chains", "price_feed", "up", "features"] {
        assert!(obj.get(hidden).is_none(), "{hidden} omitted by default");
    }

    let (st, _) = app.request("GET", "/", None, None).await;
    assert_eq!(st, StatusCode::OK, "landing HTML served when enabled");

    std::env::remove_var("PUBLIC_LANDING_ENABLED");
}

/// Walk every leaf, asserting none is a string. A string leaf is how an
/// identifier (a handle, an npub, a row id) would reach this unauthenticated
/// surface, so the shape itself is the guarantee, not a field-by-field allowlist
/// that the next field to be added would quietly escape.
fn assert_no_string_leaves(v: &serde_json::Value, path: &str) {
    match v {
        serde_json::Value::String(s) => panic!("stats leaked a string leaf at {path}: {s:?}"),
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                assert_no_string_leaves(item, &format!("{path}[{i}]"));
            }
        }
        serde_json::Value::Object(map) => {
            for (k, item) in map {
                assert_no_string_leaves(item, &format!("{path}.{k}"));
            }
        }
        _ => {}
    }
}

/// The stats block reports an aggregate and never an identifier: no handle it
/// counted appears anywhere in the response, and the block carries no strings at
/// all. Drives config directly, so it does not touch process env.
#[tokio::test]
async fn stats_report_an_aggregate_and_never_an_identifier() {
    let Some(app) = common::try_app_with(|c| {
        c.landing.enabled = true;
        c.landing.stats_enabled = true;
        // Floor of 1: the assertions below are about shape, and a test database
        // shared with other cases cannot be relied on to clear the real floor.
        c.landing.stats_min_users = 1;
    })
    .await
    else {
        return;
    };

    // Enough handles to clear the smallest bucket, so the published-count branch
    // below actually runs instead of passing vacuously on an empty database.
    let handles: Vec<String> = {
        let mut created = Vec::new();
        for _ in 0..12 {
            created.push(app.create_user_with_handle().await);
        }
        created
    };

    let (st, body) = app.request("GET", "/api/v1/server-info", None, None).await;
    assert_eq!(st, StatusCode::OK);

    let stats = body.get("stats").expect("stats block when stats are on");
    assert_no_string_leaves(stats, "stats");
    assert!(
        stats["any_handles"].as_bool().unwrap_or(false),
        "handles were just claimed: {body}"
    );

    // Nothing we created is quotable from the whole response, not just the block.
    let rendered = body.to_string();
    for handle in &handles {
        assert!(
            !rendered.contains(handle.as_str()),
            "a claimed handle reached the public surface: {body}"
        );
    }

    // The published number is a floor, never more than the truth, and coarse
    // enough that it cannot name the registration that moved it.
    let actual = app
        .state
        .db
        .get_handle_count()
        .await
        .expect("count handles");
    let published = stats
        .get("handles_at_least")
        .and_then(|v| v.as_i64())
        .expect("a count is published once the floor is cleared");
    assert!(
        published <= actual,
        "published {published} overstates {actual}"
    );
    assert_eq!(published % 10, 0, "published {published} is not coarse");

    // One more registration must not move the published block at all. A public
    // counter that ticks by one answers "did someone just register?" by
    // subtraction, which is the whole reason the value is bucketed and held.
    let _ = app.create_user_with_handle().await;
    let (st, after) = app.request("GET", "/api/v1/server-info", None, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        after.get("stats"),
        Some(stats),
        "the stats block moved with a single registration"
    );
}

/// Stats stay dark unless the operator turns them on, even with the landing
/// surface itself enabled: a new public capability defaults closed.
#[tokio::test]
async fn stats_absent_unless_enabled() {
    let Some(app) = common::try_app_with(|c| {
        c.landing.enabled = true;
        c.landing.stats_enabled = false;
    })
    .await
    else {
        return;
    };

    let _ = app.create_user_with_handle().await;
    let (st, body) = app.request("GET", "/api/v1/server-info", None, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        body.get("stats").is_none(),
        "stats block present with stats off: {body}"
    );
}
