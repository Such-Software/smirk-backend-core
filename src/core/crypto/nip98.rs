//! NIP-98 HTTP Auth verification (BIP-340 schnorr over a kind-27235 event).
//!
//! Two verifiers share one authenticated-event parse:
//!
//! * [`verify_nip98`] — LOGIN grade. Binds the request URL, method, and a
//!   `created_at` freshness window. Use it only for endpoints that read or mint
//!   a session, never for a state-changing write.
//! * [`verify_signed_action`] — STATE-CHANGE grade. Additionally binds a
//!   server-issued single-use nonce, a purpose, a canonical request descriptor
//!   hash (so empty-body DELETE/GET still bind the path + params), and an
//!   optional explicit target id and instance id. Every bound tag must appear
//!   exactly once (a duplicate is rejected, defeating a parser-differential),
//!   and all comparisons are constant-time. The single-use consumption of the
//!   nonce is the caller's responsibility (an atomic delete from the challenge
//!   store); this function only proves the signed event commits to it.
//!
//! Spec: <https://github.com/nostr-protocol/nips/blob/master/98.md>

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use k256::schnorr::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// NIP-98 HTTP-auth event kind.
const NIP98_KIND: u32 = 27235;

#[derive(Debug, Deserialize)]
struct Nip98Event {
    id: String,
    pubkey: String,
    created_at: i64,
    kind: u32,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

/// Why a token was rejected. Deliberately coarse: the handler maps all of these
/// to a single 401 so the token never becomes an oracle.
#[derive(Debug, PartialEq, Eq)]
pub enum Nip98Error {
    Malformed,
    WrongKind,
    UrlMismatch,
    MethodMismatch,
    Expired,
    BadId,
    BadSignature,
    /// A bound tag was missing.
    MissingTag,
    /// A bound tag appeared more than once (parser-differential defense).
    DuplicateTag,
    /// A bound value (nonce/purpose/payload/target/instance) did not match.
    BindingMismatch,
}

/// Constant-time string equality.
fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Find the single tag with `name`; reject if absent or duplicated.
fn exactly_one<'a>(ev: &'a Nip98Event, name: &str) -> Result<&'a str, Nip98Error> {
    let mut found: Option<&str> = None;
    for t in &ev.tags {
        if t.len() >= 2 && t[0] == name {
            if found.is_some() {
                return Err(Nip98Error::DuplicateTag);
            }
            found = Some(t[1].as_str());
        }
    }
    found.ok_or(Nip98Error::MissingTag)
}

/// Decode, structurally validate, recompute the NIP-01 id, and verify the
/// schnorr signature. Returns the event ONLY once it is authenticated, so every
/// tag a caller subsequently reads is covered by the verified signature.
fn parse_authenticated(
    header: &str,
    now: i64,
    max_age_secs: i64,
) -> Result<Nip98Event, Nip98Error> {
    let b64 = header.strip_prefix("Nostr ").ok_or(Nip98Error::Malformed)?;
    let raw = STANDARD
        .decode(b64.trim())
        .map_err(|_| Nip98Error::Malformed)?;
    let ev: Nip98Event = serde_json::from_slice(&raw).map_err(|_| Nip98Error::Malformed)?;

    if ev.kind != NIP98_KIND {
        return Err(Nip98Error::WrongKind);
    }
    // Freshness window, with saturating arithmetic so an attacker-chosen
    // (signed) created_at cannot overflow the subtraction and wrap the bound.
    if ev.created_at > now.saturating_add(max_age_secs)
        || ev.created_at < now.saturating_sub(max_age_secs)
    {
        return Err(Nip98Error::Expired);
    }

    // Recompute the NIP-01 id: sha256 of the canonical array serialization,
    // matching @smirk/core's JSON.stringify([0, pubkey, created_at, kind, tags, content]).
    let serial = serde_json::to_string(&serde_json::json!([
        0,
        ev.pubkey,
        ev.created_at,
        ev.kind,
        ev.tags,
        ev.content
    ]))
    .map_err(|_| Nip98Error::BadId)?;
    let computed = hex::encode(Sha256::digest(serial.as_bytes()));
    if computed != ev.id {
        return Err(Nip98Error::BadId);
    }

    // BIP-340 schnorr verify over the 32-byte id with the x-only pubkey.
    // Length-guard BEFORE constructing the key/sig: k256's `from_bytes` and
    // `try_from` panic on a short slice, and these fields are attacker-controlled
    // (the id is an unauthenticated hash), so a wrong length must fail closed.
    let pubkey = hex::decode(&ev.pubkey).map_err(|_| Nip98Error::BadSignature)?;
    let id_bytes = hex::decode(&ev.id).map_err(|_| Nip98Error::BadSignature)?;
    let sig_bytes = hex::decode(&ev.sig).map_err(|_| Nip98Error::BadSignature)?;
    if pubkey.len() != 32 || id_bytes.len() != 32 || sig_bytes.len() != 64 {
        return Err(Nip98Error::BadSignature);
    }
    let vk = VerifyingKey::from_bytes(&pubkey).map_err(|_| Nip98Error::BadSignature)?;
    let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|_| Nip98Error::BadSignature)?;
    vk.verify_raw(&id_bytes, &sig)
        .map_err(|_| Nip98Error::BadSignature)?;

    Ok(ev)
}

/// LOGIN-grade verification. Binds URL + method + freshness only. Returns the
/// verified x-only public key (hex).
pub fn verify_nip98(
    header: &str,
    expected_url: &str,
    expected_method: &str,
    now: i64,
    max_age_secs: i64,
) -> Result<String, Nip98Error> {
    let ev = parse_authenticated(header, now, max_age_secs)?;
    if exactly_one(&ev, "u")? != expected_url {
        return Err(Nip98Error::UrlMismatch);
    }
    if !exactly_one(&ev, "method")?.eq_ignore_ascii_case(expected_method) {
        return Err(Nip98Error::MethodMismatch);
    }
    Ok(ev.pubkey)
}

/// Canonical request descriptor bound into a signed action. Covers method,
/// path, the sorted query string, and the body hash, so an empty-body
/// DELETE/GET still binds its path and parameters. The client builds the
/// identical string and signs `sha256(descriptor)` in the `payload` tag.
pub fn request_descriptor(method: &str, path: &str, canonical_query: &str, body: &[u8]) -> String {
    let body_hash = hex::encode(Sha256::digest(body));
    format!(
        "{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path,
        canonical_query,
        body_hash
    )
}

/// Hex sha256 of a request descriptor (the value bound in the `payload` tag).
pub fn descriptor_sha256(descriptor: &str) -> String {
    hex::encode(Sha256::digest(descriptor.as_bytes()))
}

/// STATE-CHANGE-grade verification. In addition to URL/method/freshness, binds a
/// server-issued single-use nonce, a purpose, the request-descriptor hash, and
/// an optional explicit target id and instance id — each as a tag that must
/// appear exactly once, compared constant-time. Returns the verified pubkey.
///
/// Pass a tight `max_age_secs` (e.g. 30). The caller MUST also atomically
/// consume `expected_nonce` from the challenge store; this proves only that the
/// signed event commits to it.
#[allow(clippy::too_many_arguments)]
pub fn verify_signed_action(
    header: &str,
    expected_url: &str,
    expected_method: &str,
    expected_purpose: &str,
    expected_nonce: &str,
    expected_payload_sha256: &str,
    expected_target: Option<(&str, &str)>,
    expected_instance_id: Option<&str>,
    now: i64,
    max_age_secs: i64,
) -> Result<String, Nip98Error> {
    let ev = parse_authenticated(header, now, max_age_secs)?;

    if !ct_eq(exactly_one(&ev, "u")?, expected_url) {
        return Err(Nip98Error::BindingMismatch);
    }
    if !exactly_one(&ev, "method")?.eq_ignore_ascii_case(expected_method) {
        return Err(Nip98Error::BindingMismatch);
    }
    if !ct_eq(exactly_one(&ev, "purpose")?, expected_purpose) {
        return Err(Nip98Error::BindingMismatch);
    }
    if !ct_eq(exactly_one(&ev, "challenge")?, expected_nonce) {
        return Err(Nip98Error::BindingMismatch);
    }
    if !ct_eq(exactly_one(&ev, "payload")?, expected_payload_sha256) {
        return Err(Nip98Error::BindingMismatch);
    }
    if let Some((tag_name, tag_value)) = expected_target {
        if !ct_eq(exactly_one(&ev, tag_name)?, tag_value) {
            return Err(Nip98Error::BindingMismatch);
        }
    }
    if let Some(instance_id) = expected_instance_id {
        if !ct_eq(exactly_one(&ev, "instance_id")?, instance_id) {
            return Err(Nip98Error::BindingMismatch);
        }
    }

    Ok(ev.pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real token produced by @smirk/core `buildNip98Event` for NIP-06 vector 1,
    // GET /auth/me, created_at 1700000000. Proves cross-impl interop.
    const CORE_EVENT: &str = r#"{"id":"3776bd353b41e5e2da592a6161992c2906d8c248b994cdf3f5a1bc5d11820255","pubkey":"17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917","created_at":1700000000,"kind":27235,"tags":[["u","https://backend.smirk.cash/api/v1/auth/me"],["method","GET"]],"content":"","sig":"73f7fd1ad95b39c7929cbcbf8892cf7f07e18fa9950616cce5051073c960a67843348d26da1169bd0ec6a48befb8c2037ac22843ba0af96a4ab5ad1f8a76cabd"}"#;
    const URL: &str = "https://backend.smirk.cash/api/v1/auth/me";
    const PUBKEY: &str = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";

    fn login_header() -> String {
        format!("Nostr {}", STANDARD.encode(CORE_EVENT.as_bytes()))
    }

    // ── verify_nip98 (login) ───────────────────────────────────────────────

    #[test]
    fn verifies_a_core_produced_token() {
        assert_eq!(
            verify_nip98(&login_header(), URL, "GET", 1_700_000_010, 60).unwrap(),
            PUBKEY
        );
    }

    #[test]
    fn method_is_case_insensitive() {
        assert!(verify_nip98(&login_header(), URL, "get", 1_700_000_010, 60).is_ok());
    }

    #[test]
    fn rejects_wrong_url() {
        assert_eq!(
            verify_nip98(
                &login_header(),
                "https://evil.test/x",
                "GET",
                1_700_000_010,
                60
            ),
            Err(Nip98Error::UrlMismatch)
        );
    }

    #[test]
    fn rejects_wrong_method() {
        assert_eq!(
            verify_nip98(&login_header(), URL, "POST", 1_700_000_010, 60),
            Err(Nip98Error::MethodMismatch)
        );
    }

    #[test]
    fn rejects_expired() {
        assert_eq!(
            verify_nip98(&login_header(), URL, "GET", 1_700_100_000, 60),
            Err(Nip98Error::Expired)
        );
    }

    #[test]
    fn rejects_tampered_event() {
        let tampered = CORE_EVENT.replace("11820255", "11820256");
        let h = format!("Nostr {}", STANDARD.encode(tampered.as_bytes()));
        assert_eq!(
            verify_nip98(&h, URL, "GET", 1_700_000_010, 60),
            Err(Nip98Error::BadId)
        );
    }

    #[test]
    fn rejects_non_nostr_header() {
        assert_eq!(
            verify_nip98("Bearer abc", URL, "GET", 1_700_000_010, 60),
            Err(Nip98Error::Malformed)
        );
    }

    // ── verify_signed_action (state-change) ─────────────────────────────────

    /// Sign an event in-test, returning (header, pubkey_hex).
    fn sign(tags: Vec<Vec<String>>, content: &str, created_at: i64) -> (String, String) {
        use k256::schnorr::SigningKey;
        let sk = SigningKey::from_bytes(&[7u8; 32]).expect("valid scalar");
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let serial = serde_json::to_string(&serde_json::json!([
            0, pk_hex, created_at, NIP98_KIND, tags, content
        ]))
        .unwrap();
        let id = hex::encode(Sha256::digest(serial.as_bytes()));
        let id_bytes = hex::decode(&id).unwrap();
        let sig = sk.sign_raw(&id_bytes, &[0u8; 32]).expect("sign");
        let sig_hex = hex::encode(sig.to_bytes());
        let ev = serde_json::json!({
            "id": id, "pubkey": pk_hex, "created_at": created_at,
            "kind": NIP98_KIND, "tags": tags, "content": content, "sig": sig_hex
        });
        let header = format!(
            "Nostr {}",
            STANDARD.encode(serde_json::to_vec(&ev).unwrap())
        );
        (header, pk_hex)
    }

    const AURL: &str = "https://b.example/api/v1/admin/keys";
    fn payload_hash() -> String {
        descriptor_sha256(&request_descriptor(
            "POST",
            "/api/v1/admin/keys",
            "",
            b"{\"k\":1}",
        ))
    }
    fn action_tags(purpose: &str, nonce: &str, payload: &str) -> Vec<Vec<String>> {
        vec![
            vec!["u".into(), AURL.into()],
            vec!["method".into(), "POST".into()],
            vec!["purpose".into(), purpose.into()],
            vec!["challenge".into(), nonce.into()],
            vec!["payload".into(), payload.into()],
        ]
    }

    #[test]
    fn signed_action_verifies() {
        let p = payload_hash();
        let (h, pk) = sign(action_tags("admin_action", "nonce-1", &p), "", 1000);
        let got = verify_signed_action(
            &h,
            AURL,
            "POST",
            "admin_action",
            "nonce-1",
            &p,
            None,
            None,
            1000,
            30,
        )
        .unwrap();
        assert_eq!(got, pk);
    }

    #[test]
    fn signed_action_rejects_wrong_nonce() {
        let p = payload_hash();
        let (h, _) = sign(action_tags("admin_action", "nonce-1", &p), "", 1000);
        assert_eq!(
            verify_signed_action(
                &h,
                AURL,
                "POST",
                "admin_action",
                "OTHER",
                &p,
                None,
                None,
                1000,
                30
            ),
            Err(Nip98Error::BindingMismatch)
        );
    }

    #[test]
    fn signed_action_rejects_wrong_purpose() {
        let p = payload_hash();
        let (h, _) = sign(action_tags("admin_action", "nonce-1", &p), "", 1000);
        assert_eq!(
            verify_signed_action(
                &h,
                AURL,
                "POST",
                "erasure_confirm",
                "nonce-1",
                &p,
                None,
                None,
                1000,
                30
            ),
            Err(Nip98Error::BindingMismatch)
        );
    }

    #[test]
    fn signed_action_rejects_wrong_payload() {
        let p = payload_hash();
        let (h, _) = sign(action_tags("admin_action", "nonce-1", &p), "", 1000);
        let other = descriptor_sha256(&request_descriptor(
            "POST",
            "/api/v1/admin/keys",
            "",
            b"DIFFERENT",
        ));
        assert_eq!(
            verify_signed_action(
                &h,
                AURL,
                "POST",
                "admin_action",
                "nonce-1",
                &other,
                None,
                None,
                1000,
                30
            ),
            Err(Nip98Error::BindingMismatch)
        );
    }

    #[test]
    fn signed_action_rejects_duplicate_purpose_tag() {
        let p = payload_hash();
        let mut tags = action_tags("admin_action", "nonce-1", &p);
        tags.push(vec!["purpose".into(), "admin_action".into()]); // second purpose tag
        let (h, _) = sign(tags, "", 1000);
        assert_eq!(
            verify_signed_action(
                &h,
                AURL,
                "POST",
                "admin_action",
                "nonce-1",
                &p,
                None,
                None,
                1000,
                30
            ),
            Err(Nip98Error::DuplicateTag)
        );
    }

    #[test]
    fn signed_action_binds_target_id() {
        let p = payload_hash();
        let mut tags = action_tags("erasure_confirm", "nonce-1", &p);
        tags.push(vec!["erasure_id".into(), "AAAA".into()]);
        let (h, _) = sign(tags, "", 1000);
        // Correct target verifies.
        assert!(verify_signed_action(
            &h,
            AURL,
            "POST",
            "erasure_confirm",
            "nonce-1",
            &p,
            Some(("erasure_id", "AAAA")),
            None,
            1000,
            30
        )
        .is_ok());
        // Retargeting to a different id is rejected (anti proof-retargeting).
        assert_eq!(
            verify_signed_action(
                &h,
                AURL,
                "POST",
                "erasure_confirm",
                "nonce-1",
                &p,
                Some(("erasure_id", "BBBB")),
                None,
                1000,
                30
            ),
            Err(Nip98Error::BindingMismatch)
        );
    }

    #[test]
    fn signed_action_rejects_tampered_signature() {
        let p = payload_hash();
        let (h, _) = sign(action_tags("admin_action", "nonce-1", &p), "", 1000);
        // Corrupt the base64 event so the signature no longer matches the id.
        let decoded = STANDARD.decode(h.strip_prefix("Nostr ").unwrap()).unwrap();
        let mut ev: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        ev["sig"] = serde_json::json!("00".repeat(64));
        let bad = format!(
            "Nostr {}",
            STANDARD.encode(serde_json::to_vec(&ev).unwrap())
        );
        assert_eq!(
            verify_signed_action(
                &bad,
                AURL,
                "POST",
                "admin_action",
                "nonce-1",
                &p,
                None,
                None,
                1000,
                30
            ),
            Err(Nip98Error::BadSignature)
        );
    }

    // ── malformed-length / overflow hardening (regressions) ─────────────────

    #[test]
    fn rejects_short_signature_without_panic() {
        // `sig` is not in the id preimage, so the id still matches; the length
        // guard must reject a < 64-byte sig before k256's try_from panics.
        let tags = vec![
            vec!["u".into(), URL.into()],
            vec!["method".into(), "GET".into()],
        ];
        let (h, _) = sign(tags, "", 1000);
        let decoded = STANDARD.decode(h.strip_prefix("Nostr ").unwrap()).unwrap();
        let mut ev: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        ev["sig"] = serde_json::json!("00ff"); // 2 bytes
        let bad = format!(
            "Nostr {}",
            STANDARD.encode(serde_json::to_vec(&ev).unwrap())
        );
        assert_eq!(
            verify_nip98(&bad, URL, "GET", 1000, 60),
            Err(Nip98Error::BadSignature)
        );
    }

    #[test]
    fn rejects_short_pubkey_without_panic() {
        // A self-consistent id over a 2-byte pubkey: the length guard must reject
        // it before k256's from_bytes asserts length 32 and panics.
        let tags: Vec<Vec<String>> = vec![];
        let pk = "0011";
        let serial =
            serde_json::to_string(&serde_json::json!([0, pk, 1000, NIP98_KIND, tags, ""])).unwrap();
        let id = hex::encode(Sha256::digest(serial.as_bytes()));
        let ev = serde_json::json!({
            "id": id, "pubkey": pk, "created_at": 1000,
            "kind": NIP98_KIND, "tags": tags, "content": "", "sig": "00".repeat(64)
        });
        let bad = format!(
            "Nostr {}",
            STANDARD.encode(serde_json::to_vec(&ev).unwrap())
        );
        assert_eq!(
            verify_nip98(&bad, URL, "GET", 1000, 60),
            Err(Nip98Error::BadSignature)
        );
    }

    #[test]
    fn rejects_extreme_created_at_without_overflow() {
        // created_at = i64::MIN would overflow `now - created_at`; saturating math
        // must reject it as Expired rather than panic (dev) or wrap-accept (release).
        let tags = vec![
            vec!["u".into(), URL.into()],
            vec!["method".into(), "GET".into()],
        ];
        let (h, _) = sign(tags, "", i64::MIN);
        assert_eq!(
            verify_nip98(&h, URL, "GET", 1_780_000_000, 60),
            Err(Nip98Error::Expired)
        );
    }
}
