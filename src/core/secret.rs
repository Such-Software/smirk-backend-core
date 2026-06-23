//! A string secret that never reveals itself through `Debug`.
//!
//! Wrap in-memory credentials (LWS admin keys, Grin API secrets, wallet
//! passwords) carried by structs that derive `Debug` or are captured by
//! `#[instrument]`, so an accidental `{:?}` or a traced field can't leak them.
//! Read the underlying value only at the point of use via [`Secret::expose`],
//! and never log the result.

/// A redacting wrapper around a sensitive `String`.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// Wrap a sensitive value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the secret value. Call only where the value is actually consumed
    /// (e.g. building a request body); never log or format the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the secret is empty (e.g. an unconfigured credential).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::new("super-secret-admin-key");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        // The value is never present in the debug rendering.
        assert!(!format!("{s:?}").contains("super-secret"));
    }

    #[test]
    fn expose_returns_value() {
        let s = Secret::new("value");
        assert_eq!(s.expose(), "value");
        assert!(!s.is_empty());
        assert!(Secret::new("").is_empty());
    }
}
