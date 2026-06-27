//! L1 integration: the public landing surface (operator §2.3). Default-OFF; when
//! on, the default projection is the minimal `{ software.name, status }` and `/`
//! serves HTML. One sequential test (it toggles process env).

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
