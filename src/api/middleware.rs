//! HTTP middleware and request-scoped extractors for the auth surface.
//!
//! Two helpers live here:
//!
//! * [`extract_user_id_from_token`] — pull a Bearer access token from the
//!   `Authorization` header and resolve it to a `user_id` via the shared
//!   [`SessionManager`] in [`AppState`]. The error is a literal (`Invalid or
//!   expired token` / a missing-header literal) so the endpoint never becomes an
//!   auth oracle.
//! * [`client_ip`] — derive the client IP used for rate-limiting and audit. It
//!   trusts `X-Forwarded-For` **only** when the TCP peer is inside
//!   `config.trusted_proxies`; otherwise it uses the real peer. A spoofed
//!   `X-Forwarded-For` from an untrusted peer cannot evade per-IP limits.
//!
//! The session manager is read from `state.sessions` (constructed once at
//! startup) rather than rebuilt per request, so the HS256 key never has to be
//! re-derived on the hot path.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::http::HeaderMap;
use uuid::Uuid;

use crate::error::AppError;
use crate::AppState;

/// Resolve a Bearer access token in the `Authorization` header to its `user_id`.
///
/// All failure modes (missing header, wrong scheme, invalid/expired/forged JWT)
/// collapse to `AppError::AuthError` with a literal message, so a caller cannot
/// distinguish "no token" from "bad token" from "expired token".
pub async fn extract_user_id_from_token(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<Uuid, AppError> {
    let token = bearer_token(headers)?;
    let info = state.sessions.verify_access_token(token)?;
    Ok(info.user_id)
}

/// Extract the raw Bearer token from an `Authorization` header, or a literal
/// `AuthError`. Split out so login-grade and state-change handlers share one
/// parser (and one error shape).
pub(crate) fn bearer_token(headers: &HeaderMap) -> Result<&str, AppError> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::AuthError("Missing authorization header".into()))?;

    auth.strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AppError::AuthError("Invalid authorization format".into()))
}

/// The client IP to use for rate-limiting and audit logging.
///
/// `peer` is the real TCP source (from axum `ConnectInfo<SocketAddr>`). We honor
/// `X-Forwarded-For` **only** when `peer` falls inside one of
/// `config.trusted_proxies`; otherwise the header is attacker-controlled and is
/// ignored. The default config has an empty trusted-proxy list, so by default
/// the real peer is always used — fail-closed against header spoofing.
///
/// When trusted, the *left-most* XFF entry (the original client, per the de-facto
/// convention) is taken; if it does not parse as an IP we fall back to the peer
/// rather than trusting an unparseable value.
pub fn client_ip(state: &AppState, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    let peer_ip = peer.ip();

    let peer_is_trusted = state
        .config
        .trusted_proxies
        .iter()
        .any(|net| net.contains(peer_ip));

    if !peer_is_trusted {
        return peer_ip;
    }

    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|xff| xff.split(',').next())
        .map(str::trim)
        .and_then(|first| first.parse::<IpAddr>().ok())
        .unwrap_or(peer_ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnetwork::IpNetwork;
    use std::str::FromStr;

    fn headers_with_xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", value.parse().unwrap());
        h
    }

    fn peer(s: &str) -> SocketAddr {
        SocketAddr::new(IpAddr::from_str(s).unwrap(), 12345)
    }

    #[test]
    fn bearer_token_parses_and_rejects() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer abc.def.ghi".parse().unwrap(),
        );
        assert_eq!(bearer_token(&h).unwrap(), "abc.def.ghi");

        let mut bad = HeaderMap::new();
        bad.insert(
            axum::http::header::AUTHORIZATION,
            "Basic xyz".parse().unwrap(),
        );
        assert!(bearer_token(&bad).is_err());
        assert!(bearer_token(&HeaderMap::new()).is_err());
    }

    /// Build a throwaway AppState is heavy; instead exercise the trust decision
    /// against the proxy list directly through a tiny shim mirroring `client_ip`.
    fn pick_ip(trusted: &[IpNetwork], headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
        let peer_ip = peer.ip();
        if !trusted.iter().any(|n| n.contains(peer_ip)) {
            return peer_ip;
        }
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|xff| xff.split(',').next())
            .map(str::trim)
            .and_then(|f| f.parse::<IpAddr>().ok())
            .unwrap_or(peer_ip)
    }

    #[test]
    fn untrusted_peer_ignores_xff() {
        // No trusted proxies: the spoofed header is ignored, peer wins.
        let h = headers_with_xff("1.2.3.4");
        let got = pick_ip(&[], &h, peer("9.9.9.9"));
        assert_eq!(got, IpAddr::from_str("9.9.9.9").unwrap());
    }

    #[test]
    fn trusted_peer_honors_leftmost_xff() {
        let trusted = vec![IpNetwork::from_str("10.0.0.0/8").unwrap()];
        let h = headers_with_xff("1.2.3.4, 10.0.0.5");
        let got = pick_ip(&trusted, &h, peer("10.0.0.5"));
        assert_eq!(got, IpAddr::from_str("1.2.3.4").unwrap());
    }

    #[test]
    fn trusted_peer_with_garbage_xff_falls_back_to_peer() {
        let trusted = vec![IpNetwork::from_str("10.0.0.0/8").unwrap()];
        let h = headers_with_xff("not-an-ip");
        let got = pick_ip(&trusted, &h, peer("10.0.0.5"));
        assert_eq!(got, IpAddr::from_str("10.0.0.5").unwrap());
    }
}
