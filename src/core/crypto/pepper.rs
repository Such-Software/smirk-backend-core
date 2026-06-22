//! Domain-separated HMAC peppering for identity values stored at rest.
//!
//! `pubkey_hash` and `seed_fingerprint` are deterministic, client-reproducible
//! values (anyone with a candidate seed/pubkey can recompute them). Storing them
//! raw turns the database — and `/auth/check-restore` — into a seed-existence
//! oracle and a cross-instance linker. Peppering with a server-held HMAC key
//! makes the stored value non-reproducible without the pepper, while staying
//! deterministic for the server's own lookups. The domain string separates
//! namespaces so the same input under two domains yields unrelated outputs.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// `hex(HMAC-SHA256(pepper, domain || 0x1f || value))`.
pub fn peppered_hex(pepper: &str, domain: &str, value: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(pepper.as_bytes()).expect("HMAC accepts any key length");
    mac.update(domain.as_bytes());
    mac.update(&[0x1f]); // unit separator: unambiguous domain/value boundary
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        assert_eq!(
            peppered_hex("pep", "pubkey_hash", "abc"),
            peppered_hex("pep", "pubkey_hash", "abc")
        );
    }

    #[test]
    fn domain_separated() {
        assert_ne!(
            peppered_hex("pep", "pubkey_hash", "abc"),
            peppered_hex("pep", "seed_fingerprint", "abc")
        );
    }

    #[test]
    fn keyed_by_pepper() {
        assert_ne!(
            peppered_hex("pep-A", "d", "abc"),
            peppered_hex("pep-B", "d", "abc")
        );
    }

    #[test]
    fn no_delimiter_collision() {
        // The 0x1f separator prevents (domain="a", value="bc") colliding with
        // (domain="ab", value="c").
        assert_ne!(
            peppered_hex("pep", "a", "bc"),
            peppered_hex("pep", "ab", "c")
        );
    }
}
