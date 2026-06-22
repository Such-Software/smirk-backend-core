//! NIP-05 directory hosting: serves `/.well-known/nostr.json`.
//!
//! This is the directory half of NIP-05. It resolves a Smirk `username` to the
//! Nostr pubkey the user has linked (the `nostr_pubkey` column, set via
//! `POST /api/v1/auth/nostr/link`), and pairs with the wallet-side resolver
//! (`@smirk/core` `resolveNip05`) so Smirk users become findable by any Nostr
//! client.
//!
//! Behavior is intentionally enumeration-safe and non-failing for the public
//! lookup surface:
//!
//! * Usernames are stored lowercased (see `users::set_username`), so the `?name=`
//!   query is lowercased before lookup.
//! * An unknown name, an unlinked user, or a missing `name` parameter all return
//!   the SAME empty document (`{"names":{},"relays":{}}`) — never a 404 and never
//!   an error — so the endpoint does not disclose which usernames exist.
//! * Foreign error detail (sqlx) is the only thing routed to `AppError`; the
//!   client-facing failure messages are literals.
//!
//! This module mounts at the SERVER ROOT, not under `/api/v1`: NIP-05 mandates
//! the well-known path `/.well-known/nostr.json`. The application is expected to
//! `merge` [`routes`] into the root router (alongside the `/api/v1`-nested
//! routers).
//!
//! Spec: <https://github.com/nostr-protocol/nips/blob/master/05.md>

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::error::AppError;
use crate::AppState;

// ── constants ─────────────────────────────────────────────────────────────────

/// Default relay hints advertised in the well-known `relays` map.
///
/// Public relays shared with other wallets so cross-wallet delivery works before
/// any per-user relay list is configured. NIP-05 lets a server advertise relay
/// hints per pubkey in the `relays` object; we serve the same default set for
/// every resolved name.
///
/// TODO(phase-2): make configurable and serve per-user lists (NIP-65 kind 10002
/// / NIP-17 inbox relays) when private-message delivery lands.
const DEFAULT_RELAYS: &[&str] = &["wss://relay.damus.io", "wss://nos.lol"];

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// Query for `GET /.well-known/nostr.json`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct WellKnownQuery {
    /// The local part to resolve (NIP-05 `?name=`). Absent or unknown resolves to
    /// an empty document rather than an error.
    pub name: Option<String>,
}

/// NIP-05 well-known document.
///
/// * `names` maps each resolved local part to its x-only Nostr pubkey (hex).
/// * `relays` maps each returned pubkey to a list of recommended relay URLs.
///
/// Both maps are empty when the name is unknown, unlinked, or omitted.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct WellKnownResponse {
    /// `{ local_part: nostr_pubkey_hex }`. Empty when nothing resolved.
    pub names: HashMap<String, String>,
    /// `{ nostr_pubkey_hex: [relay_url, ...] }`. Empty when nothing resolved.
    pub relays: HashMap<String, Vec<String>>,
}

// ── GET /.well-known/nostr.json ────────────────────────────────────────────────

/// NIP-05 resolution for Smirk usernames.
///
/// Looks up the user by lowercased `?name=` and, if they have a linked
/// `nostr_pubkey`, returns it in `names` (with the default relay hints under
/// `relays`). An unknown name, an unlinked user, or an absent `name` parameter
/// all return an empty document — this endpoint never errors on the lookup path
/// and never discloses which usernames exist.
#[utoipa::path(
    get,
    path = "/.well-known/nostr.json",
    params(
        ("name" = Option<String>, Query, description = "NIP-05 local part to resolve")
    ),
    responses(
        (status = 200, description = "NIP-05 directory document (empty when unresolved)", body = WellKnownResponse)
    ),
    tag = "nip05"
)]
#[instrument(skip(state))]
pub async fn well_known_nostr(
    State(state): State<Arc<AppState>>,
    Query(q): Query<WellKnownQuery>,
) -> Result<Json<WellKnownResponse>, AppError> {
    let mut names = HashMap::new();
    let mut relays = HashMap::new();

    if let Some(raw) = q.name {
        // Usernames are stored lowercased (see users::set_username).
        let name = raw.to_lowercase();
        if let Some(user) = state.db.get_user_by_username(&name).await? {
            if let Some(pubkey) = user.nostr_pubkey {
                relays.insert(
                    pubkey.clone(),
                    DEFAULT_RELAYS.iter().map(|r| r.to_string()).collect(),
                );
                names.insert(name, pubkey);
            }
        }
    }

    Ok(Json(WellKnownResponse { names, relays }))
}

// ── router ─────────────────────────────────────────────────────────────────────

/// NIP-05 route, mounted at the SERVER ROOT (NOT under `/api/v1`). NIP-05
/// mandates the well-known path verbatim, so the application is expected to
/// `merge` this into the root router rather than nest it under `/api/v1`.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/.well-known/nostr.json", get(well_known_nostr))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The query field is optional: `name` round-trips when present and defaults
    /// to `None` when absent.
    #[test]
    fn well_known_query_wire_shape() {
        let with_name: WellKnownQuery =
            serde_json::from_str(r#"{"name":"alice"}"#).expect("name parses");
        assert_eq!(with_name.name.as_deref(), Some("alice"));

        let empty: WellKnownQuery = serde_json::from_str("{}").expect("empty parses");
        assert!(empty.name.is_none());
    }

    /// Default relay hints are well-formed `wss://` URLs.
    #[test]
    fn default_relays_are_wss() {
        assert!(!DEFAULT_RELAYS.is_empty());
        assert!(DEFAULT_RELAYS.iter().all(|r| r.starts_with("wss://")));
    }

    /// The response serializes to the exact NIP-05 wire shape, and an empty
    /// document is `{"names":{},"relays":{}}` (never `null`).
    #[test]
    fn response_serializes_to_nip05_shape() {
        let empty = WellKnownResponse {
            names: HashMap::new(),
            relays: HashMap::new(),
        };
        let json = serde_json::to_value(&empty).unwrap();
        assert_eq!(json, serde_json::json!({ "names": {}, "relays": {} }));

        let mut names = HashMap::new();
        names.insert("alice".to_string(), "abc123".to_string());
        let mut relays = HashMap::new();
        relays.insert(
            "abc123".to_string(),
            vec!["wss://relay.damus.io".to_string()],
        );
        let json = serde_json::to_value(&WellKnownResponse { names, relays }).unwrap();
        assert_eq!(json["names"]["alice"], "abc123");
        assert_eq!(json["relays"]["abc123"][0], "wss://relay.damus.io");
    }
}
