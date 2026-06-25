//! L1 integration: the public capabilities endpoint.

mod common;

use axum::http::StatusCode;

#[tokio::test]
async fn capabilities_is_public_and_well_shaped() {
    let app = require_app!();
    // No token required — the wallet reads this before/without login.
    let (status, body) = app.request("GET", "/api/v1/capabilities", None, None).await;
    assert_eq!(status, StatusCode::OK);

    assert!(body["version"].as_str().is_some(), "version present");
    // Every chain reports an `enabled` boolean.
    for chain in ["btc", "ltc", "xmr", "wow", "grin"] {
        assert!(
            body["chains"][chain]["enabled"].is_boolean(),
            "chain {chain} reports enabled"
        );
    }
    // UTXO chains carry a network; CryptoNote/Grin report null.
    for chain in ["btc", "ltc"] {
        assert!(
            body["chains"][chain]["network"].as_str().is_some(),
            "{chain} carries a network"
        );
    }
    for chain in ["xmr", "wow", "grin"] {
        assert!(
            body["chains"][chain]["network"].is_null(),
            "{chain} network is null"
        );
    }
    // Feature flags are present.
    for feat in ["grin_relay", "prices", "nostr_identity", "tips"] {
        assert!(
            body["features"][feat].is_boolean(),
            "feature {feat} reports a boolean"
        );
    }
}
