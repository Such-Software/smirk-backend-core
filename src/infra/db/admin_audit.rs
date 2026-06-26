//! Tamper-evident audit chain for privileged actions.
//!
//! Each appended row's `row_hash = HMAC(secret, prev_hash ‖ canonical(row))`,
//! linking it to the previous row; a boot/`doctor` check walks the chain and
//! detects any edit, deletion, or reorder. Appends serialize on a transaction
//! advisory lock so `seq` and `prev_hash` cannot race. The append takes a
//! `&mut PgConnection`, so a caller can run its state change and the audit row in
//! ONE transaction — making the audit write fail-closed (roll back together)
//! rather than a best-effort side effect.

use chrono::{DateTime, SubsecRound, Utc};
use sqlx::PgConnection;
use tracing::instrument;
use uuid::Uuid;

use crate::core::crypto::pepper::peppered_hex;
use crate::error::AppError;
use crate::models::db::{AdminAuditLog, NewAdminAudit};

use super::Database;

/// First-row predecessor hash.
const GENESIS: &str = "smirk-admin-audit-genesis";
/// Fixed key for the per-append transaction advisory lock.
const CHAIN_LOCK_KEY: i64 = 0x5311_4D17_4155_0117;

const COLS: &str = "id, seq, action, actor_kind, actor_pubkey_prefix, target, \
     details, ip_address, created_at, prev_hash, row_hash";

/// `HMAC(secret, "admin_audit" ‖ prev_hash ‖ canonical-fields)`. The canonical
/// form is a JSON array (unambiguous escaping); timestamps are microsecond epochs.
fn chain_hash(
    secret: &str,
    prev_hash: &str,
    seq: i64,
    e: &NewAdminAudit,
    created_at: DateTime<Utc>,
) -> String {
    let ip = e.ip_address.map(|i| i.to_string());
    let canonical = serde_json::json!([
        seq,
        e.action,
        e.actor_kind,
        e.actor_pubkey_prefix,
        e.target,
        e.details,
        ip,
        created_at.timestamp_micros(),
    ])
    .to_string();
    peppered_hex(
        secret,
        "admin_audit",
        &format!("{prev_hash}\u{1f}{canonical}"),
    )
}

fn row_as_new(r: &AdminAuditLog) -> NewAdminAudit {
    NewAdminAudit {
        action: r.action.clone(),
        actor_kind: r.actor_kind.clone(),
        actor_pubkey_prefix: r.actor_pubkey_prefix.clone(),
        target: r.target.clone(),
        details: r.details.clone(),
        ip_address: r.ip_address,
    }
}

impl Database {
    /// Append a privileged-action row to the chain, ON THE CALLER'S connection so
    /// it can be part of the same transaction as the state change it records.
    /// Pass `&mut *tx`. The advisory lock requires this to run inside a tx.
    #[instrument(skip(self, conn, entry, secret), fields(action = %entry.action))]
    pub async fn append_admin_audit(
        &self,
        conn: &mut PgConnection,
        entry: &NewAdminAudit,
        secret: &str,
    ) -> Result<AdminAuditLog, AppError> {
        // Serialize appends so seq/prev_hash cannot race (released at tx end).
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(CHAIN_LOCK_KEY)
            .execute(&mut *conn)
            .await?;

        let last: Option<(i64, String)> =
            sqlx::query_as("SELECT seq, row_hash FROM admin_audit_logs ORDER BY seq DESC LIMIT 1")
                .fetch_optional(&mut *conn)
                .await?;
        let (prev_seq, prev_hash) = last.unwrap_or((0, GENESIS.to_string()));
        let seq = prev_seq + 1;
        let created_at = Utc::now().trunc_subsecs(6);
        let row_hash = chain_hash(secret, &prev_hash, seq, entry, created_at);

        let sql = format!(
            "INSERT INTO admin_audit_logs \
             (id, seq, action, actor_kind, actor_pubkey_prefix, target, details, ip_address, created_at, prev_hash, row_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING {COLS}"
        );
        let row = sqlx::query_as::<_, AdminAuditLog>(&sql)
            .bind(Uuid::new_v4())
            .bind(seq)
            .bind(&entry.action)
            .bind(&entry.actor_kind)
            .bind(&entry.actor_pubkey_prefix)
            .bind(&entry.target)
            .bind(&entry.details)
            .bind(entry.ip_address)
            .bind(created_at)
            .bind(&prev_hash)
            .bind(&row_hash)
            .fetch_one(&mut *conn)
            .await?;
        Ok(row)
    }

    /// Append a row in its own transaction (standalone audit, e.g. the CLI path).
    #[instrument(skip(self, entry, secret), fields(action = %entry.action))]
    pub async fn record_admin_audit(
        &self,
        entry: &NewAdminAudit,
        secret: &str,
    ) -> Result<AdminAuditLog, AppError> {
        let mut tx = self.pool().begin().await?;
        let row = self.append_admin_audit(&mut tx, entry, secret).await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Walk the chain in order and verify every link. Returns `false` on any
    /// edited field, deleted row (seq gap), reorder, or broken linkage.
    #[instrument(skip(self, secret))]
    pub async fn verify_admin_audit_chain(&self, secret: &str) -> Result<bool, AppError> {
        let sql = format!("SELECT {COLS} FROM admin_audit_logs ORDER BY seq ASC");
        let rows = sqlx::query_as::<_, AdminAuditLog>(&sql)
            .fetch_all(self.pool())
            .await?;

        let mut prev = GENESIS.to_string();
        for (i, row) in rows.iter().enumerate() {
            // Rows are seq-ordered and gap-free from 1; index pins the expected seq.
            let expected_seq = i as i64 + 1;
            if row.seq != expected_seq || row.prev_hash != prev {
                return Ok(false);
            }
            let recomputed = chain_hash(
                secret,
                &row.prev_hash,
                row.seq,
                &row_as_new(row),
                row.created_at,
            );
            if recomputed != row.row_hash {
                return Ok(false);
            }
            prev = row.row_hash.clone();
        }
        Ok(true)
    }

    /// Most-recent privileged-action rows (newest first), for the admin panel.
    #[instrument(skip(self))]
    pub async fn list_admin_audit(&self, limit: i64) -> Result<Vec<AdminAuditLog>, AppError> {
        let sql = format!("SELECT {COLS} FROM admin_audit_logs ORDER BY seq DESC LIMIT $1");
        let rows = sqlx::query_as::<_, AdminAuditLog>(&sql)
            .bind(limit)
            .fetch_all(self.pool())
            .await?;
        Ok(rows)
    }
}
