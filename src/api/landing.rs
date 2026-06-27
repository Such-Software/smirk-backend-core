//! Public landing page + `server-info` read model (operator §2.3).
//!
//! Treated as ONE fingerprint surface, not N independent fields. Default-OFF
//! (`PUBLIC_LANDING_ENABLED`); when on, the default public set is minimal —
//! `{ software.name, status }` — and every other field is individually opt-in.
//! Built from a hand-written allowlist struct (never by serializing config or
//! state), so a secret can't leak by accident. The enabled-feature tuple is
//! NEVER emitted anonymously here (connected clients use `/capabilities`).

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;

use crate::config::Config;
use crate::AppState;

#[derive(Debug, Serialize)]
pub struct Software {
    pub name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PriceFeedInfo {
    pub enabled: bool,
}

/// The public projection. Optional fields are omitted unless explicitly opted in,
/// so the default JSON is exactly `{ "software": { "name": ... }, "status": ... }`.
#[derive(Debug, Serialize)]
pub struct ServerInfo {
    pub software: Software,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_feed: Option<PriceFeedInfo>,
    /// Boolean `up` only (never an uptime duration — reboot timing is recon).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<bool>,
}

/// Coarse `major.minor` (patch is recon-only).
fn coarse_version() -> String {
    let v = env!("CARGO_PKG_VERSION");
    let mut parts = v.split('.');
    match (parts.next(), parts.next()) {
        (Some(major), Some(minor)) => format!("{major}.{minor}"),
        _ => v.to_string(),
    }
}

fn enabled_chain_symbols(config: &Config) -> Vec<String> {
    // Use the SAME serviceability predicate as /capabilities, so the public
    // landing never advertises a chain that capabilities reports as off.
    ["btc", "ltc", "xmr", "wow", "grin"]
        .iter()
        .filter(|sym| crate::api::capabilities::chain_serviceable(config, sym))
        .map(|sym| sym.to_string())
        .collect()
}

/// Build the public projection from config, honoring each per-field toggle.
pub fn build_server_info(config: &Config) -> ServerInfo {
    let l = &config.landing;
    ServerInfo {
        software: Software {
            name: "smirk-backend-core",
            version: l.expose_version.then(coarse_version),
        },
        status: "ok",
        title: l.title.clone(),
        chains: l.expose_chains.then(|| enabled_chain_symbols(config)),
        price_feed: l.expose_price_feed.then_some(PriceFeedInfo {
            enabled: config.features.prices,
        }),
        up: l.expose_uptime.then_some(true),
    }
}

/// `GET /api/v1/server-info` — the landing read model. A BARE `404` when landing
/// is off (matching an unmatched route — the `{error,code}` envelope would itself
/// hint the route exists, so it is deliberately not used here).
pub async fn server_info(State(state): State<Arc<AppState>>) -> Response {
    if !state.config.landing.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(build_server_info(&state.config)).into_response()
}

/// `GET /` — minimal HTML rendered from the read model; bare `404` when off.
pub async fn root(State(state): State<Arc<AppState>>) -> Response {
    if !state.config.landing.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let title = state
        .config
        .landing
        .title
        .as_deref()
        .unwrap_or("smirk-backend-core");
    let t = html_escape(title);
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{t}</title></head><body><h1>{t}</h1><p>status: ok</p></body></html>"
    );
    Html(html).into_response()
}

/// Minimal HTML entity escaping for the operator-supplied title.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// `server-info` route, RELATIVE to the `/api/v1` mount point. Public.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/server-info", get(server_info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_neutralizes_script() {
        assert_eq!(
            html_escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
    }
}
