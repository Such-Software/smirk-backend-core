//! Public landing page + `server-info` read model (operator §2.3).
//!
//! Treated as ONE fingerprint surface, not N independent fields. Default-OFF
//! (`PUBLIC_LANDING_ENABLED`); when on, the default public set is minimal —
//! `{ software.name, status }` — and every other field is individually opt-in.
//! Built from a hand-written allowlist struct (never by serializing config or
//! state), so a secret can't leak by accident. The enabled-feature tuple is
//! NEVER emitted anonymously here (connected clients use `/capabilities`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use tokio::sync::RwLock;

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

/// Aggregate public stats. Every field is a bool or a count and NOTHING here is
/// a string, so no handle, npub or row id can reach this unauthenticated surface
/// even by a careless later edit. The NIP-05 handler next door deliberately
/// answers identically for known and unknown names; a stats field that named or
/// narrowed to a person would be the enumeration oracle that endpoint refuses to
/// be.
#[derive(Debug, Clone, Serialize)]
pub struct StatsInfo {
    /// Whether ANY handle has been claimed on this instance. Below the
    /// k-anonymity floor this is the only thing the block says.
    pub any_handles: bool,
    /// Claimed handles, rounded DOWN to a coarse bucket: the real count is at or
    /// above this. Omitted entirely below `PUBLIC_STATS_MIN_USERS`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handles_at_least: Option<i64>,
}

/// Last computed stats block and when it was computed. See [`MIN_STATS_CACHE`]
/// for why the value is held still rather than recomputed per request.
pub type StatsCache = Arc<RwLock<Option<(Instant, StatsInfo)>>>;

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
    /// Aggregate stats; present only when `PUBLIC_STATS_ENABLED` is on. Filled by
    /// the handler, not by [`build_server_info`], because it needs a database read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<StatsInfo>,
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
        stats: None,
    }
}

/// Floor the stats block is held at, whatever the operator sets. A live counter
/// answers "did someone register in the last minute?" by subtraction, which is
/// exactly what the bucketing exists to prevent, so `PUBLIC_STATS_CACHE_HOURS`
/// is clamped UP to this and never down.
const MIN_STATS_CACHE: Duration = Duration::from_secs(3600);

/// Coarse step for [`bucket_floor`]: every step is a multiple of ten, so a
/// published number can never move by a single registration.
fn bucket_step(n: i64) -> i64 {
    match n {
        n if n < 1_000 => 10,
        n if n < 10_000 => 100,
        _ => 1_000,
    }
}

/// Round DOWN to a coarse bucket. Down, never nearest: the published number is
/// then a floor the instance can always stand behind, and it never implies
/// registrations that did not happen.
fn bucket_floor(n: i64) -> i64 {
    let step = bucket_step(n);
    n - n.rem_euclid(step)
}

/// The stats block, served from cache while that is still fresh.
///
/// `None` means the block is omitted: a count that cannot be read must not take
/// the whole landing read model down with it.
async fn stats_block(state: &AppState) -> Option<StatsInfo> {
    let (ttl, min_users) = {
        let c = state.cfg();
        (
            Duration::from_secs(c.landing.stats_cache_hours.saturating_mul(3600))
                .max(MIN_STATS_CACHE),
            c.landing.stats_min_users,
        )
    };

    if let Some((computed_at, info)) = state.stats_cache.read().await.as_ref() {
        if computed_at.elapsed() < ttl {
            return Some(info.clone());
        }
    }

    let handles = match state.db.get_handle_count().await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "handle count failed; omitting the stats block");
            return None;
        }
    };

    // Under the floor even a bucketed count narrows to a handful of people, and a
    // bucket that rounds to zero says nothing anyway; publish only the boolean.
    let info = StatsInfo {
        any_handles: handles > 0,
        handles_at_least: (handles >= min_users)
            .then(|| bucket_floor(handles))
            .filter(|bucketed| *bucketed > 0),
    };
    *state.stats_cache.write().await = Some((Instant::now(), info.clone()));
    Some(info)
}

/// `GET /api/v1/server-info` — the landing read model. A BARE `404` when landing
/// is off (matching an unmatched route — the `{error,code}` envelope would itself
/// hint the route exists, so it is deliberately not used here).
pub async fn server_info(State(state): State<Arc<AppState>>) -> Response {
    let (enabled, stats_enabled) = {
        let c = state.cfg();
        (c.landing.enabled, c.landing.stats_enabled)
    };
    if !enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut info = build_server_info(&state.cfg());
    if stats_enabled {
        info.stats = stats_block(&state).await;
    }
    Json(info).into_response()
}

/// `GET /` — minimal HTML rendered from the read model; bare `404` when off.
pub async fn root(State(state): State<Arc<AppState>>) -> Response {
    if !state.cfg().landing.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let cfg = state.cfg();
    let title = cfg.landing.title.as_deref().unwrap_or("smirk-backend-core");
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

    /// Walk every leaf of the value, asserting none of them is a string. A string
    /// leaf is how an identifier (a handle, an npub, a row id) would reach a
    /// public surface, so the shape itself is the guarantee.
    fn assert_no_string_leaves(v: &serde_json::Value, path: &str) {
        match v {
            serde_json::Value::String(s) => {
                panic!("stats leaked a string leaf at {path}: {s:?}")
            }
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

    #[test]
    fn stats_block_is_aggregate_only_and_names_no_one() {
        let json = serde_json::to_value(StatsInfo {
            any_handles: true,
            handles_at_least: Some(bucket_floor(1_234)),
        })
        .expect("serialize");
        assert_no_string_leaves(&json, "stats");
        // The published count is coarse, so it cannot move by one registration.
        let published = json["handles_at_least"].as_i64().expect("count");
        assert_eq!(published % 10, 0, "published count is coarse: {published}");
    }

    #[test]
    fn suppressed_stats_block_still_names_no_one() {
        // The below-the-floor shape: a bare boolean, nothing else.
        let json = serde_json::to_value(StatsInfo {
            any_handles: true,
            handles_at_least: None,
        })
        .expect("serialize");
        assert_no_string_leaves(&json, "stats");
        assert!(
            json.get("handles_at_least").is_none(),
            "suppressed count is omitted, not zeroed: {json}"
        );
    }

    #[test]
    fn bucket_floor_never_overstates_and_stays_coarse() {
        for n in [0i64, 1, 9, 10, 19, 137, 999, 1_000, 9_999, 10_000, 123_456] {
            let bucketed = bucket_floor(n);
            assert!(bucketed <= n, "{bucketed} overstates {n}");
            assert!(bucketed >= 0, "{bucketed} went negative for {n}");
            assert_eq!(bucketed % 10, 0, "{bucketed} is not coarse for {n}");
            assert!(
                n - bucketed < bucket_step(n),
                "{bucketed} is more than one step below {n}"
            );
        }
    }

    #[test]
    fn bucket_floor_is_monotonic_so_the_count_cannot_run_backwards() {
        let mut previous = 0;
        for n in 0..3_000 {
            let bucketed = bucket_floor(n);
            assert!(bucketed >= previous, "bucket fell from {previous} at {n}");
            previous = bucketed;
        }
    }
}
