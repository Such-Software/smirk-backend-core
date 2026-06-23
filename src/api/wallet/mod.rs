//! Wallet (chain-access) handlers: thin authenticated proxies over the per-chain
//! infra clients. The backend is non-custodial — these endpoints relay reads and
//! finalized broadcasts; all key handling and signing happen in the wallet.
//!
//! Each chain family lives in its own submodule and contributes its routes here.

use std::sync::Arc;

use axum::Router;

use crate::error::AppError;
use crate::AppState;

pub mod btc_ltc;
pub mod xmr_wow;

/// All wallet routes, RELATIVE to the `/api/v1` mount point.
pub fn routes() -> Router<Arc<AppState>> {
    btc_ltc::routes().merge(xmr_wow::routes())
}

// ── shared input validators ───────────────────────────────────────────────────
//
// These bound client-supplied values at the API boundary before they reach a
// chain client. They never reveal secret content (length/charset only).

/// Even-length hex within `max` bytes, non-empty. `field` names the value for the
/// error message (never the value itself).
pub(crate) fn validate_hex(value: &str, field: &str, max: usize) -> Result<(), AppError> {
    if value.is_empty() || value.len() > max {
        return Err(AppError::ValidationError(format!(
            "{field} has invalid length"
        )));
    }
    if !value.len().is_multiple_of(2) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::ValidationError(format!(
            "{field} must be even-length hexadecimal"
        )));
    }
    Ok(())
}

/// A Monero/Wownero private view key: 32 bytes = 64 hex chars. Validated only by
/// shape; never logged.
pub(crate) fn validate_view_key(view_key: &str) -> Result<(), AppError> {
    if view_key.len() != 64 || !view_key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::ValidationError(
            "view_key must be 64 hexadecimal characters".into(),
        ));
    }
    Ok(())
}

/// A CryptoNote address — base58, ~95 (standard) to ~106 (integrated) chars.
/// Bounded generously; the LWS does full validation.
pub(crate) fn validate_cn_address(address: &str) -> Result<(), AppError> {
    if address.is_empty() || address.len() > 256 {
        return Err(AppError::ValidationError(
            "address has invalid length".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_validation() {
        assert!(validate_hex("deadbeef", "tx", 100).is_ok());
        assert!(validate_hex("", "tx", 100).is_err());
        assert!(validate_hex("abc", "tx", 100).is_err()); // odd
        assert!(validate_hex("zz", "tx", 100).is_err()); // non-hex
        assert!(validate_hex("aaaa", "tx", 2).is_err()); // too long
    }

    #[test]
    fn view_key_validation() {
        assert!(validate_view_key(&"a".repeat(64)).is_ok());
        assert!(validate_view_key(&"a".repeat(63)).is_err());
        assert!(validate_view_key(&"z".repeat(64)).is_err()); // non-hex
    }

    #[test]
    fn cn_address_validation() {
        assert!(
            validate_cn_address("4AdkPJoxn7JCvAby9szgnt93MSEwdnxdhaASxbTBm6x5dCwmsDep").is_ok()
        );
        assert!(validate_cn_address("").is_err());
        assert!(validate_cn_address(&"x".repeat(257)).is_err());
    }
}
