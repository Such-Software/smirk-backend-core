//! Proof-of-work signup gate (ALTCHA v2, PBKDF2/SHA-256).
//!
//! Makes mass account creation *expensive* rather than perfectly Sybil-proof:
//! a legitimate signup pays ~1-2s of client CPU; the server verifies in <2ms.
//! Feature-gated via config (`FEATURE_POW`); the HMAC key is required when
//! enabled (config validation rejects a missing/placeholder key — there is no
//! source-visible fallback). Wire protocol matches the wallet's `altcha-lib`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// Solutions already spent, keyed by the challenge's HMAC signature (unique per
/// issued challenge, and covered by the HMAC we verify, so a replay cannot alter
/// it) and valued by when the spend was recorded. Entries older than the
/// challenge TTL are dropped: past that point the signed expiry rejects the
/// payload anyway, so the map is bounded by the number of DISTINCT solves inside
/// one TTL window, each of which cost an attacker a full solve.
///
/// In-process, like the website-challenge store on `AppState`: the verify path is
/// synchronous and holds no database handle, so a shared store is the
/// load-balanced-fleet path. Within one node a solve is spent exactly once.
fn spent_solutions() -> &'static Mutex<HashMap<String, Instant>> {
    static SPENT: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    SPENT.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record `signature` as spent, returning `false` if it already was. The prune
/// and the spend happen inside ONE locked section, so two concurrent
/// verifications of the same solution cannot both win: the loser's insert finds
/// the winner's entry and is rejected.
fn spend_solution(signature: &str) -> bool {
    let now = Instant::now();
    let ttl = Duration::from_secs(CHALLENGE_TTL_SECONDS);
    // A poisoned lock only means some other thread panicked while holding it; the
    // map itself is still consistent, and refusing to serve would turn a panic
    // elsewhere into a permanent registration outage.
    let lock = spent_solutions().lock();
    let mut spent = lock.unwrap_or_else(PoisonError::into_inner);
    spent.retain(|_, seen| now.duration_since(*seen) < ttl);
    // `insert` hands back the previous value, so `None` proves this solve had not
    // been spent yet: the first caller through the lock wins, every later one is
    // told to re-fetch a challenge.
    spent.insert(signature.to_string(), now).is_none()
}

/// Verify a client-submitted solution. `Ok(())` only on a valid, unexpired,
/// correctly-signed solution that has NOT been presented before.
///
/// Single use matters as much as the work itself: the signature stays valid for
/// the whole [`CHALLENGE_TTL_SECONDS`] window, so without spending the challenge
/// one solve would pay for unlimited registrations and the gate would cost an
/// attacker nothing per account.
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

    // The signature names the challenge this solution belongs to. `verify_solution`
    // has just proved it is ours and unexpired, so a missing one is unreachable;
    // fail closed anyway rather than spending an empty key.
    let signature = payload.challenge.signature.as_deref().ok_or_else(|| {
        AppError::ValidationError("PoW solution rejected (missing signature)".into())
    })?;
    if !spend_solution(signature) {
        return Err(AppError::ValidationError(
            "PoW solution rejected (already used; re-fetch the challenge)".into(),
        ));
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
    fn solution_is_single_use() {
        let cfg = test_cfg();
        let p = solve(&cfg);
        verify_payload(&cfg, &p).expect("first use accepted");
        // The signed challenge stays valid for its whole TTL, so replay protection
        // is the only thing between one solve and unlimited registrations.
        assert!(
            verify_payload(&cfg, &p).is_err(),
            "a spent solution must not verify a second time"
        );
    }

    #[test]
    fn concurrent_uses_of_one_solution_have_one_winner() {
        let cfg = test_cfg();
        let p = solve(&cfg);
        // Both racers are spawned before either is joined, so they contend for the
        // same solve; the spend is atomic, so the loser must be rejected outright
        // rather than both being let through.
        let (first, second) = std::thread::scope(|scope| {
            let a = scope.spawn(|| verify_payload(&cfg, &p).is_ok());
            let b = scope.spawn(|| verify_payload(&cfg, &p).is_ok());
            (a.join().unwrap(), b.join().unwrap())
        });
        assert_ne!(first, second, "exactly one racer may spend a solve");
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
