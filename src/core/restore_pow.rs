//! Restore proof-of-work — a hashcash gate sized to the RESTORE DEPTH.
//!
//! A wallet importing a foreign seed pays compute proportional to the chain-scan
//! cost it imposes on the operator's LWS/node: deeper restore ⇒ more work. This
//! is the "pay for what you cost the operator" mechanism (see the restore-policy
//! decision), distinct from the ALTCHA registration gate ([`crate::core::pow`]).
//!
//! It is deliberately self-contained — no server-issued challenge, no state —
//! because the work is bound to the restore parameters themselves: a solved
//! nonce satisfies the difficulty ONLY for this exact `(asset, address,
//! start_height)`, so it cannot be precomputed generically, replayed against a
//! different account, or down-graded to a shallower (cheaper) restore.

use sha2::{Digest, Sha256};

/// Domain tag so a restore-PoW hash can never collide with another protocol hash.
const DOMAIN: &[u8] = b"smirk-restore-pow-v1";

/// The hashcash preimage (minus the nonce) that pins the work to one restore.
fn challenge_input(asset: &str, address: &str, start_height: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(DOMAIN.len() + asset.len() + address.len() + 16);
    v.extend_from_slice(DOMAIN);
    v.push(0x1f);
    v.extend_from_slice(asset.as_bytes());
    v.push(0x1f);
    v.extend_from_slice(address.as_bytes());
    v.push(0x1f);
    v.extend_from_slice(&start_height.to_le_bytes());
    v
}

/// Leading zero BITS of a digest — the hashcash difficulty metric (each bit
/// doubles expected solver work).
fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut n = 0;
    for &b in digest {
        if b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

/// Verify a restore-PoW nonce: `sha256(domain ‖ asset ‖ address ‖ start_height ‖
/// nonce)` must have at least `required_bits` leading zero bits.
/// `required_bits == 0` (no pricing / within the free depth) accepts anything.
pub fn verify(
    asset: &str,
    address: &str,
    start_height: u64,
    nonce: u64,
    required_bits: u32,
) -> bool {
    if required_bits == 0 {
        return true;
    }
    let mut hasher = Sha256::new();
    hasher.update(challenge_input(asset, address, start_height));
    hasher.update(nonce.to_le_bytes());
    leading_zero_bits(&hasher.finalize()) >= required_bits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brute-force the first satisfying nonce (small difficulty → fast).
    fn solve(asset: &str, address: &str, h: u64, bits: u32) -> u64 {
        (0u64..)
            .find(|&n| verify(asset, address, h, n, bits))
            .unwrap()
    }

    #[test]
    fn solve_then_verify_roundtrips() {
        let n = solve("xmr", "Wo123", 100, 8);
        assert!(verify("xmr", "Wo123", 100, n, 8));
    }

    #[test]
    fn zero_bits_accepts_any_nonce() {
        assert!(verify("xmr", "addr", 1, 0, 0));
        assert!(verify("xmr", "addr", 1, 12345, 0));
    }

    #[test]
    fn unsolved_nonce_fails_high_difficulty() {
        // A fixed un-mined nonce essentially never clears a 20-bit bar (~1/2^20).
        assert!(!verify("xmr", "addr", 100, 0, 20));
    }

    #[test]
    fn nonce_is_bound_to_restore_params() {
        let n = solve("xmr", "addrA", 100, 12);
        assert!(verify("xmr", "addrA", 100, n, 12));
        // The same nonce against a different address recomputes an independent
        // hash, which must not meet the SAME bar (false-accept ~1/2^12).
        assert!(!verify("xmr", "addrB", 100, n, 12));
        assert!(!verify("wow", "addrA", 100, n, 12));
        assert!(!verify("xmr", "addrA", 101, n, 12));
    }
}
