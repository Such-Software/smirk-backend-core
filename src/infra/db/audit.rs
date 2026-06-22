//! Audit log queries.
//!
//! Append-only record of security-relevant actions (logins, session lifecycle,
//! wallet registration, broadcasts). Explicit column lists (no `SELECT *`) keep
//! the row shape pinned to the `AuditLog` struct.

use ipnetwork::IpNetwork;
use tracing::instrument;
use uuid::Uuid;

use crate::error::AppError;
use crate::models::db::{AuditAction, AuditLog, NewAuditLog};

use super::Database;

/// Explicit `audit_logs` columns (matches `AuditLog`; FromRow maps by name).
const AUDIT_LOG_COLS: &str = "id, user_id, action, resource_type, resource_id, \
     details, ip_address, user_agent, created_at";

impl Database {
    /// Insert an audit log entry.
    #[instrument(skip(self, input), fields(action = ?input.action))]
    pub async fn create_audit_log(&self, input: NewAuditLog) -> Result<AuditLog, AppError> {
        let sql = format!(
            "INSERT INTO audit_logs \
             (user_id, action, resource_type, resource_id, details, ip_address, user_agent) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {AUDIT_LOG_COLS}"
        );
        let log = sqlx::query_as::<_, AuditLog>(&sql)
            .bind(input.user_id)
            .bind(input.action)
            .bind(&input.resource_type)
            .bind(input.resource_id)
            .bind(&input.details)
            .bind(input.ip_address)
            .bind(&input.user_agent)
            .fetch_one(self.pool())
            .await?;
        Ok(log)
    }

    /// Record an action without returning the inserted row (convenience wrapper).
    #[allow(clippy::too_many_arguments)]
    pub async fn log_action(
        &self,
        user_id: Option<Uuid>,
        action: AuditAction,
        resource_type: Option<&str>,
        resource_id: Option<Uuid>,
        details: Option<serde_json::Value>,
        ip_address: Option<IpNetwork>,
        user_agent: Option<&str>,
    ) -> Result<(), AppError> {
        self.create_audit_log(NewAuditLog {
            user_id,
            action,
            resource_type: resource_type.map(String::from),
            resource_id,
            details,
            ip_address,
            user_agent: user_agent.map(String::from),
        })
        .await?;
        Ok(())
    }

    /// Fetch a user's most recent audit entries (newest first). When `action` is
    /// `Some`, restricts to that action; otherwise returns all actions.
    #[instrument(skip(self))]
    pub async fn get_user_audit_logs(
        &self,
        user_id: Uuid,
        action: Option<AuditAction>,
        limit: i64,
    ) -> Result<Vec<AuditLog>, AppError> {
        let sql = format!(
            "SELECT {AUDIT_LOG_COLS} FROM audit_logs \
             WHERE user_id = $1 AND ($2::audit_action IS NULL OR action = $2) \
             ORDER BY created_at DESC LIMIT $3"
        );
        let logs = sqlx::query_as::<_, AuditLog>(&sql)
            .bind(user_id)
            .bind(action)
            .bind(limit)
            .fetch_all(self.pool())
            .await?;
        Ok(logs)
    }
}
