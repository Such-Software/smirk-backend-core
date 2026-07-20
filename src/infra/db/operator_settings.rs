//! Operator settings overlay storage (`operator_settings`) — the DB tier under the
//! env-derived Config. One MAC'd JSONB row per section (`doc` = that section's sparse
//! patch). Loads verify the MAC per section (fail-closed: a tampered/undecodable
//! section is ignored and falls back to env); writes upsert + append to the
//! hash-chained admin_audit log in one transaction. Mirrors `server_config` (MAC) and
//! `admin_keys::create_admin_key_audited` (audited write).

use chrono::{SubsecRound, Utc};
use serde_json::Value;
use subtle::ConstantTimeEq;
use tracing::{instrument, warn};
use uuid::Uuid;

use crate::config_overlay::SettingsOverlay;
use crate::core::crypto::pepper::peppered_hex;
use crate::error::AppError;
use crate::models::db::{NewAdminAudit, OperatorSettingRow};

use super::Database;

/// Recursively key-sorted, whitespace-free JSON so the MAC is stable across Postgres
/// JSONB normalization (JSONB does NOT preserve object key order). Both write and read
/// canonicalize the same way, so the MAC round-trips regardless of storage reordering.
fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

/// `HMAC(secret, "operator_settings" ‖ section ‖ version ‖ canonical(doc))`.
fn settings_mac(secret: &str, section: &str, version: i64, doc: &Value) -> String {
    peppered_hex(
        secret,
        "operator_settings",
        &format!("{section}\u{1f}{version}\u{1f}{}", canonical_json(doc)),
    )
}

fn verify_settings_mac(secret: &str, row: &OperatorSettingRow) -> bool {
    let expected = settings_mac(secret, &row.section, row.version, &row.doc);
    expected
        .as_bytes()
        .ct_eq(row.integrity_mac.as_bytes())
        .into()
}

impl Database {
    /// Load + verify all settings rows into a [`SettingsOverlay`]. A row whose MAC
    /// fails, or whose section fails to deserialize, is IGNORED (that section falls
    /// back to env) and logged — never fails the caller. Fail-closed on tamper,
    /// fail-open-to-env on a bad/absent section.
    #[instrument(skip(self, secret))]
    pub async fn load_settings_overlay(&self, secret: &str) -> Result<SettingsOverlay, AppError> {
        let rows = sqlx::query_as::<_, OperatorSettingRow>(
            "SELECT section, doc, version, updated_by, updated_at, integrity_mac \
             FROM operator_settings",
        )
        .fetch_all(self.pool())
        .await?;

        let mut merged = serde_json::Map::new();
        for row in &rows {
            if !verify_settings_mac(secret, row) {
                warn!(section = %row.section, "operator_settings MAC mismatch; ignoring section (env-only)");
                continue;
            }
            merged.insert(row.section.clone(), row.doc.clone());
        }
        match serde_json::from_value::<SettingsOverlay>(Value::Object(merged)) {
            Ok(ov) => Ok(ov),
            Err(e) => {
                warn!(error = %e, "operator_settings overlay decode failed; using env-only");
                Ok(SettingsOverlay::default())
            }
        }
    }

    /// Upsert one section's `doc` (new MAC + bumped version) and append the audit entry
    /// in a single transaction. Returns the new version. The caller MUST have already
    /// validated the resulting effective config via `Config::apply_overlay` (this only
    /// persists). `FOR UPDATE` serializes concurrent writers to the same section.
    #[instrument(skip(self, doc, audit, secret))]
    pub async fn put_setting_audited(
        &self,
        section: &str,
        doc: &Value,
        updated_by: Option<Uuid>,
        expected_version: Option<i64>,
        audit: &NewAdminAudit,
        secret: &str,
    ) -> Result<i64, AppError> {
        let mut tx = self.pool().begin().await?;

        let current: Option<i64> = sqlx::query_scalar(
            "SELECT version FROM operator_settings WHERE section = $1 FOR UPDATE",
        )
        .bind(section)
        .fetch_optional(&mut *tx)
        .await?;
        let cur = current.unwrap_or(0);
        // Optimistic concurrency: reject a stale write (two operators editing at once).
        if let Some(exp) = expected_version {
            if cur != exp {
                tx.rollback().await?;
                return Err(AppError::Conflict(format!(
                    "settings section '{section}' changed concurrently (expected v{exp}, found v{cur}); reload and retry"
                )));
            }
        }
        let version = cur + 1;
        let mac = settings_mac(secret, section, version, doc);
        let updated_at = Utc::now().trunc_subsecs(6);

        sqlx::query(
            "INSERT INTO operator_settings \
               (section, doc, version, updated_by, updated_at, integrity_mac) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (section) DO UPDATE SET \
               doc = EXCLUDED.doc, version = EXCLUDED.version, \
               updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at, \
               integrity_mac = EXCLUDED.integrity_mac",
        )
        .bind(section)
        .bind(doc)
        .bind(version)
        .bind(updated_by)
        .bind(updated_at)
        .bind(&mac)
        .execute(&mut *tx)
        .await?;

        self.append_admin_audit(&mut tx, audit, secret).await?;
        tx.commit().await?;
        Ok(version)
    }

    /// Current persisted version per section (for optimistic-concurrency PUTs + the
    /// GET response). A section with no row is absent (its effective source is env).
    pub async fn settings_versions(
        &self,
    ) -> Result<std::collections::HashMap<String, i64>, AppError> {
        let rows: Vec<(String, i64)> =
            sqlx::query_as("SELECT section, version FROM operator_settings")
                .fetch_all(self.pool())
                .await?;
        Ok(rows.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_is_key_order_independent() {
        let a = json!({"b": 1, "a": {"y": 2, "x": [3, 2]}});
        let b = json!({"a": {"x": [3, 2], "y": 2}, "b": 1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
    }

    #[test]
    fn settings_mac_changes_with_version_and_doc() {
        let doc = json!({"enabled": true});
        let m1 = settings_mac("secret-secret-secret-secret-32ch", "landing", 1, &doc);
        let m2 = settings_mac("secret-secret-secret-secret-32ch", "landing", 2, &doc);
        let m3 = settings_mac(
            "secret-secret-secret-secret-32ch",
            "landing",
            1,
            &json!({"enabled": false}),
        );
        assert_ne!(m1, m2);
        assert_ne!(m1, m3);
    }
}
