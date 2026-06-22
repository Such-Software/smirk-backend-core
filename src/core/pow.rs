//! Proof-of-work signup gate (ALTCHA v2, PBKDF2/SHA-256).
//!
//! Makes mass account creation *expensive* rather than perfectly Sybil-proof:
//! a legitimate signup pays ~1-2s of client CPU; the server verifies in <2ms.
//! Feature-gated via config (`FEATURE_POW`); the HMAC key is required when
//! enabled (config validation rejects a missing/placeholder key — there is no
//! source-visible fallback). Wire protocol matches the wallet's `altcha-lib`.

use std::time::{SystemTime, UNIX_EPOCH};

use altcha::{
    create_challenge, verify_solution, CreateChallengeOptions, Payload, VerifySolutionOptions,
};

use crate::config::PowConfig;
use crate::error::AppError;

/// Challenge TTL: long enough for a slow phone, short enough to bound an
/// attacker's pre-solve window before the HMAC key rotates.
const CHALLENGE_TTL_SECONDS: u64 = 600;

/// Whether a registration from this BTC pubkey hash must present a valid PoW
/// solution: when the global gate is on, or this pubkey is individually opted in.
pub fn required_for(cfg: &PowConfig, pubkey_hash: &str) -> bool {
    cfg.required || cfg.required_for_pubkeys.iter().any(|p| p == pubkey_hash)
}

/// Issue a fresh challenge. The HMAC signature embeds an expiry, so the gate is
/// stateless: no issued-challenge store is needed for expiry.
pub fn issue_challenge(cfg: &PowConfig) -> Result<altcha::Challenge, AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let opts = CreateChallengeOptions {
        algorithm: "PBKDF2/SHA-256".to_string(),
        cost: cfg.cost as u32,
        expires_at: Some(now + CHALLENGE_TTL_SECONDS),
        hmac_signature_secret: Some(cfg.hmac_key.clone()),
        ..Default::default()
    };
    create_challenge(opts)
        .map_err(|e| AppError::Internal(format!("PoW challenge creation failed: {}", e)))
}

/// Verify a client-submitted solution. `Ok(())` only on a valid, unexpired,
/// correctly-signed solution.
pub fn verify_payload(cfg: &PowConfig, payload: &Payload) -> Result<(), AppError> {
    let opts =
        VerifySolutionOptions::new(&payload.challenge, &payload.solution, cfg.hmac_key.as_str());
    let result = verify_solution(opts)
        .map_err(|e| AppError::ValidationError(format!("PoW verify failed: {}", e)))?;
    if !result.verified {
        let reason = if result.expired {
            "challenge expired (re-fetch the challenge)"
        } else if result.invalid_signature.unwrap_or(false) {
            "invalid signature"
        } else if result.invalid_solution.unwrap_or(false) {
            "wrong solution"
        } else {
            "rejected"
        };
        return Err(AppError::ValidationError(format!(
            "PoW solution rejected ({})",
            reason
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use altcha::{solve_challenge, SolveChallengeOptions};

    fn test_cfg() -> PowConfig {
        PowConfig {
            enabled: true,
            hmac_key: "test-hmac-key-32-bytes-of-secret!".to_string(),
            required: true,
            cost: 100, // tiny so tests stay fast
            required_for_pubkeys: vec![],
        }
    }

    fn solve(cfg: &PowConfig) -> Payload {
        let challenge = issue_challenge(cfg).expect("issue");
        let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
            .expect("solve")
            .expect("solution found");
        Payload {
            challenge,
            solution,
        }
    }

    #[test]
    fn issue_solve_verify_roundtrips() {
        let cfg = test_cfg();
        verify_payload(&cfg, &solve(&cfg)).expect("valid solution verifies");
    }

    #[test]
    fn tampered_signature_rejected() {
        let cfg = test_cfg();
        let mut p = solve(&cfg);
        p.challenge.signature = Some("ff".repeat(32));
        assert!(verify_payload(&cfg, &p).is_err());
    }

    #[test]
    fn wrong_secret_rejected() {
        let cfg = test_cfg();
        let p = solve(&cfg);
        let attacker = PowConfig {
            hmac_key: "a-completely-different-secret-key!".to_string(),
            ..test_cfg()
        };
        assert!(verify_payload(&attacker, &p).is_err());
    }

    #[test]
    fn solution_not_replayable_across_challenges() {
        let cfg = test_cfg();
        let a = solve(&cfg);
        let b_challenge = issue_challenge(&cfg).expect("issue b");
        let crossed = Payload {
            challenge: b_challenge,
            solution: a.solution,
        };
        assert!(verify_payload(&cfg, &crossed).is_err());
    }

    #[test]
    fn missing_signature_rejected() {
        let cfg = test_cfg();
        let mut p = solve(&cfg);
        p.challenge.signature = None;
        assert!(verify_payload(&cfg, &p).is_err());
    }

    #[test]
    fn required_for_respects_global_and_per_pubkey() {
        let mut cfg = PowConfig {
            required: false,
            required_for_pubkeys: vec!["abcd1234".to_string()],
            ..test_cfg()
        };
        assert!(required_for(&cfg, "abcd1234"));
        assert!(!required_for(&cfg, "deadbeef"));
        cfg.required = true;
        assert!(required_for(&cfg, "deadbeef"));
    }
}
