//! Centralized error handling.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Application error types.
///
/// Every error that can surface from a handler is represented here. Variants
/// fall into two buckets for response rendering (see [`IntoResponse`]): LEAKY
/// variants carry an internal/system string that is logged privately and
/// replaced with a generic public message; SAFE variants carry an
/// operator-authored, user-facing message surfaced verbatim.
#[derive(Debug)]
pub enum AppError {
    /// Configuration error (missing env var, invalid value).
    ConfigError(String),
    /// Database error (connection, query failure).
    DatabaseError(String),
    /// Authentication error (invalid token, expired session).
    AuthError(String),
    /// Blockchain node error (connection, RPC failure).
    NodeError(String),
    /// Validation error (invalid input).
    ValidationError(String),
    /// Resource not found.
    NotFound(String),
    /// Access forbidden (authenticated but not authorized).
    Forbidden(String),
    /// Conflict: a unique resource (e.g. a username) is already taken.
    Conflict(String),
    /// Rate limit exceeded.
    RateLimited,
    /// Internal server error.
    Internal(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            Self::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            Self::AuthError(msg) => write!(f, "Authentication error: {}", msg),
            Self::NodeError(msg) => write!(f, "Node error: {}", msg),
            Self::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            Self::NotFound(msg) => write!(f, "Not found: {}", msg),
            Self::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            Self::Conflict(msg) => write!(f, "Conflict: {}", msg),
            Self::RateLimited => write!(f, "Rate limited"),
            Self::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl AppError {
    /// Machine-readable error code for programmatic handling by clients.
    fn error_code(&self) -> &'static str {
        match self {
            AppError::ConfigError(_) => "INTERNAL_ERROR",
            AppError::DatabaseError(_) => "INTERNAL_ERROR",
            AppError::AuthError(_) => "AUTH_ERROR",
            AppError::NodeError(_) => "NODE_UNAVAILABLE",
            AppError::ValidationError(_) => "VALIDATION_ERROR",
            AppError::NotFound(_) => "NOT_FOUND",
            AppError::Forbidden(_) => "FORBIDDEN",
            AppError::Conflict(_) => "CONFLICT",
            AppError::RateLimited => "RATE_LIMITED",
            AppError::Internal(_) => "INTERNAL_ERROR",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = self.error_code();

        // CWE-209: never echo raw `sqlx::Error` / `reqwest::Error` / config
        // strings back to the client — they can leak DB schema, connection
        // strings, internal hostnames, and similar detail.
        //
        //   * LEAKY — carry an internal/system error string. Log it privately
        //     via tracing; return a generic public message.
        //   * SAFE  — carry an operator-authored, user-facing message already
        //     deemed safe to surface. These MUST be string literals at the call
        //     site (never an interpolated foreign error), or they become an
        //     information oracle.
        let (status, message) = match &self {
            // --- LEAKY variants: log private, return generic ---
            AppError::ConfigError(inner) => {
                tracing::error!(error = %inner, code = %code, "internal error in handler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AppError::DatabaseError(inner) => {
                tracing::error!(error = %inner, code = %code, "internal error in handler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AppError::NodeError(inner) => {
                tracing::error!(error = %inner, code = %code, "internal error in handler");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Upstream node unavailable".to_string(),
                )
            }
            AppError::Internal(inner) => {
                tracing::error!(error = %inner, code = %code, "internal error in handler");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }

            // --- SAFE variants: operator-authored, surface verbatim ---
            AppError::AuthError(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()),
        };

        let body = Json(json!({
            "error": message,
            "code": code,
        }));

        (status, body).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::DatabaseError(err.to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        AppError::NodeError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    //! Regression tests for CWE-209 (information exposure via raw error
    //! strings). For each LEAKY variant, build an `AppError` whose inner
    //! message contains obviously-internal markers (hostnames, ports,
    //! secret-looking tokens) and assert the JSON body does NOT echo them —
    //! only a generic public message — while the structured `code` is
    //! preserved. For SAFE variants, verify the operator-authored message IS
    //! surfaced verbatim so we don't over-redact.
    use super::*;
    use axum::body::to_bytes;

    async fn extract_json(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("read error response body");
        let json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("error response is valid JSON");
        (status, json)
    }

    #[tokio::test]
    async fn database_error_does_not_leak_raw_message() {
        let err = AppError::DatabaseError(
            "connection refused to db 'smirk_internal' at host db.internal:5432".into(),
        );
        let (status, json) = extract_json(err.into_response()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let error_msg = json["error"].as_str().unwrap();
        assert!(
            !error_msg.contains("smirk_internal"),
            "leaked internal db name: {error_msg}"
        );
        assert!(
            !error_msg.contains("db.internal"),
            "leaked internal hostname: {error_msg}"
        );
        assert!(!error_msg.contains("5432"), "leaked port: {error_msg}");
        assert_eq!(json["code"].as_str().unwrap(), "INTERNAL_ERROR");
    }

    #[tokio::test]
    async fn node_error_does_not_leak_raw_message() {
        let err = AppError::NodeError(
            "RPC call to noded at 10.0.0.42:18081 failed: auth token 'sk_live_abc123' rejected"
                .into(),
        );
        let (status, json) = extract_json(err.into_response()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let error_msg = json["error"].as_str().unwrap();
        assert!(
            !error_msg.contains("10.0.0.42"),
            "leaked internal IP: {error_msg}"
        );
        assert!(!error_msg.contains("18081"), "leaked port: {error_msg}");
        assert!(
            !error_msg.contains("sk_live_abc123"),
            "leaked secret-looking token: {error_msg}"
        );
        assert_eq!(json["code"].as_str().unwrap(), "NODE_UNAVAILABLE");
    }

    #[tokio::test]
    async fn config_error_does_not_leak_raw_message() {
        let err = AppError::ConfigError(
            "JWT_SECRET=super_secret_value_42 has invalid length at /etc/smirk/secrets.env".into(),
        );
        let (status, json) = extract_json(err.into_response()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let error_msg = json["error"].as_str().unwrap();
        assert!(
            !error_msg.contains("JWT_SECRET"),
            "leaked env var name: {error_msg}"
        );
        assert!(
            !error_msg.contains("super_secret_value_42"),
            "leaked secret value: {error_msg}"
        );
        assert_eq!(json["code"].as_str().unwrap(), "INTERNAL_ERROR");
    }

    #[tokio::test]
    async fn validation_error_surfaces_operator_authored_message() {
        let msg = "amount must be greater than zero";
        let err = AppError::ValidationError(msg.into());
        let (status, json) = extract_json(err.into_response()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"].as_str().unwrap(), msg);
        assert_eq!(json["code"].as_str().unwrap(), "VALIDATION_ERROR");
    }

    #[tokio::test]
    async fn conflict_surfaces_message_and_409() {
        // SAFE variant: a taken/reserved username comes back as 409 with the
        // CONFLICT code clients match on — distinct from the 500 a blanket
        // sqlx::Error conversion would otherwise produce.
        let msg = "That username is not available";
        let err = AppError::Conflict(msg.into());
        let (status, json) = extract_json(err.into_response()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json["error"].as_str().unwrap(), msg);
        assert_eq!(json["code"].as_str().unwrap(), "CONFLICT");
    }
}
