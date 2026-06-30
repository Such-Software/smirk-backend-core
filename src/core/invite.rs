//! Registration invite codes: generation + hashing.
//!
//! A code is 16 random bytes (128 bits) rendered as base58 for legible operator
//! distribution. Only `sha256(code)` is ever stored (see [`crate::infra::db`]);
//! the raw code is shown once, at mint time. 128 bits of entropy makes the
//! stored hash non-brute-forceable, so no pepper is needed (unlike user-chosen
//! secrets). Single-use is enforced by an atomic claim in the db layer.

use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate a fresh random invite code (128-bit, base58).
pub fn generate_invite_code() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bs58::encode(bytes).into_string()
}

/// Hex `sha256` of a raw invite code — the stored form and the lookup key.
pub fn hash_invite_code(code: &str) -> String {
    hex::encode(Sha256::digest(code.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_hex64() {
        let h = hash_invite_code("abc");
        assert_eq!(h, hash_invite_code("abc"));
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(h, hash_invite_code("abd"));
    }

    #[test]
    fn generated_codes_are_unique_and_nonempty() {
        let a = generate_invite_code();
        let b = generate_invite_code();
        assert!(!a.is_empty());
        assert_ne!(a, b);
        // base58 of 16 bytes is ~22 chars; never trivially short.
        assert!(a.len() >= 16);
    }
}
