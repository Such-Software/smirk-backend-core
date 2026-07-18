//! Operator-editable settings overlay — the DB precedence tier under the env-derived
//! [`Config`] (effective = defaults -> env -> DB overlay). A [`SettingsOverlay`] is a
//! SPARSE patch: one `Option<*Overlay>` per editable section, each a struct of
//! `Option<T>` NON-SECRET fields (absent = "leave as env"). Secrets are excluded BY
//! CONSTRUCTION — no overlay field maps to a secret sub-struct — so the admin plane can
//! neither read nor set one. [`Config::apply_overlay`] merges an overlay onto the
//! env-derived config and re-runs the SAME [`Config::validate`] boot uses, so a bad edit
//! fails identically and nothing invalid is ever applied. Pure over `Config`.

use serde::{Deserialize, Serialize};

use crate::config::{Config, RestartApplyMode, RestorePolicy};
use crate::error::AppError;

/// Sparse patch over the env-derived [`Config`]. Each section is independent; a `None`
/// (absent) section leaves that whole group at its env value. Unknown sections/fields
/// are ignored on load (forward-compat); the PUT path validates before persisting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SettingsOverlay {
    pub landing: Option<LandingOverlay>,
    pub retention: Option<RetentionOverlay>,
    pub restore: Option<RestoreOverlay>,
    pub console: Option<ConsoleOverlay>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LandingOverlay {
    pub enabled: Option<bool>,
    /// Empty string clears the title (env `None`); any other value sets it.
    pub title: Option<String>,
    pub expose_version: Option<bool>,
    pub expose_chains: Option<bool>,
    pub expose_price_feed: Option<bool>,
    pub expose_uptime: Option<bool>,
    pub stats_enabled: Option<bool>,
    pub stats_cache_hours: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RetentionOverlay {
    pub login_events_days: Option<u64>,
    pub audit_days: Option<u64>,
    /// Gates a boot-spawned sweep worker -> RESTART-REQUIRED (see `runtime_class`).
    pub erasure_enabled: Option<bool>,
    pub purge_login_events: Option<bool>,
    pub export_per_day: Option<u32>,
    pub grace_period_hours: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RestoreOverlay {
    /// One of `create-only` | `bounded` | `unlimited`.
    pub policy: Option<String>,
    pub max_depth_days: Option<u32>,
    pub pow_free_days: Option<u32>,
    pub pow_days_per_bit: Option<u32>,
    pub pow_max_bits: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ConsoleOverlay {
    /// How a restart-required config change applies: `manual` | `auto`.
    pub restart_apply_mode: Option<String>,
}

/// Whether a changed field applies live or needs a restart. Drives BOTH the hot-swap
/// decision and the `GET /admin/config` annotation — the single source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeClass {
    /// Re-read off the effective config on the next request; hot-swappable.
    RuntimeSafe,
    /// Captured by a boot-built client/socket/worker; applied on graceful restart.
    RestartRequired,
}

/// Classify one `(section, field)`. Unknown pairs default to `RestartRequired` (the
/// safe default: never hot-swap something whose consumers we haven't reasoned about).
pub fn runtime_class(section: &str, field: &str) -> RuntimeClass {
    use RuntimeClass::*;
    match (section, field) {
        // erasure_enabled gates a boot-spawned sweep worker; a live flip would desync
        // the worker from the request gate.
        ("retention", "erasure_enabled") => RestartRequired,
        ("landing", _) => RuntimeSafe,
        ("retention", _) => RuntimeSafe,
        ("restore", _) => RuntimeSafe,
        ("console", _) => RuntimeSafe,
        _ => RestartRequired,
    }
}

impl Config {
    /// Merge a settings overlay onto this (env-derived) config, then re-run the SAME
    /// validation boot uses. Returns the candidate effective config, or the identical
    /// [`AppError`] boot would raise — so a bad edit is rejected BEFORE anything
    /// persists and can never brick the instance. Pure: does not mutate `self`.
    pub fn apply_overlay(&self, ov: &SettingsOverlay) -> Result<Config, AppError> {
        let mut c = self.clone();

        if let Some(l) = &ov.landing {
            if let Some(v) = l.enabled {
                c.landing.enabled = v;
            }
            if let Some(v) = &l.title {
                c.landing.title = if v.is_empty() { None } else { Some(v.clone()) };
            }
            if let Some(v) = l.expose_version {
                c.landing.expose_version = v;
            }
            if let Some(v) = l.expose_chains {
                c.landing.expose_chains = v;
            }
            if let Some(v) = l.expose_price_feed {
                c.landing.expose_price_feed = v;
            }
            if let Some(v) = l.expose_uptime {
                c.landing.expose_uptime = v;
            }
            if let Some(v) = l.stats_enabled {
                c.landing.stats_enabled = v;
            }
            if let Some(v) = l.stats_cache_hours {
                c.landing.stats_cache_hours = v;
            }
        }

        if let Some(r) = &ov.retention {
            if let Some(v) = r.login_events_days {
                c.retention.login_events_days = v;
            }
            if let Some(v) = r.audit_days {
                c.retention.audit_days = v;
            }
            if let Some(v) = r.erasure_enabled {
                c.retention.erasure_enabled = v;
            }
            if let Some(v) = r.purge_login_events {
                c.retention.purge_login_events = v;
            }
            if let Some(v) = r.export_per_day {
                c.retention.export_per_day = v;
            }
            if let Some(v) = r.grace_period_hours {
                c.retention.grace_period_hours = v;
            }
        }

        if let Some(r) = &ov.restore {
            if let Some(p) = &r.policy {
                c.restore.policy = match p.as_str() {
                    "create-only" => RestorePolicy::CreateOnly,
                    "bounded" => RestorePolicy::Bounded,
                    "unlimited" => RestorePolicy::Unlimited,
                    other => {
                        return Err(AppError::ValidationError(format!(
                            "invalid restore.policy {other:?} (want create-only|bounded|unlimited)"
                        )))
                    }
                };
            }
            if let Some(v) = r.max_depth_days {
                c.restore.max_depth_days = v;
            }
            if let Some(v) = r.pow_free_days {
                c.restore.pow_free_days = v;
            }
            if let Some(v) = r.pow_days_per_bit {
                c.restore.pow_days_per_bit = v;
            }
            if let Some(v) = r.pow_max_bits {
                c.restore.pow_max_bits = v;
            }
        }

        if let Some(cs) = &ov.console {
            if let Some(m) = &cs.restart_apply_mode {
                c.console.restart_apply_mode = match m.as_str() {
                    "manual" => RestartApplyMode::Manual,
                    "auto" => RestartApplyMode::Auto,
                    other => {
                        return Err(AppError::ValidationError(format!(
                            "invalid console.restart_apply_mode {other:?} (want manual|auto)"
                        )))
                    }
                };
            }
        }

        c.validate()?;
        Ok(c)
    }
}

/// Every operator-editable `(section, field)` pair — the enumerable surface for
/// `GET /admin/config` (per-field runtime_class) and for classifying a PUT patch.
pub const EDITABLE_FIELDS: &[(&str, &str)] = &[
    ("landing", "enabled"),
    ("landing", "title"),
    ("landing", "expose_version"),
    ("landing", "expose_chains"),
    ("landing", "expose_price_feed"),
    ("landing", "expose_uptime"),
    ("landing", "stats_enabled"),
    ("landing", "stats_cache_hours"),
    ("retention", "login_events_days"),
    ("retention", "audit_days"),
    ("retention", "erasure_enabled"),
    ("retention", "purge_login_events"),
    ("retention", "export_per_day"),
    ("retention", "grace_period_hours"),
    ("restore", "policy"),
    ("restore", "max_depth_days"),
    ("restore", "pow_free_days"),
    ("restore", "pow_days_per_bit"),
    ("restore", "pow_max_bits"),
    ("console", "restart_apply_mode"),
];

impl Config {
    /// A fully-populated overlay reflecting the EFFECTIVE value of every editable
    /// field (all `Some`). `GET /admin/config` returns this so the console shows
    /// current values; diffing against the persisted overlay yields each field's
    /// source (default/env vs db).
    pub fn editable_overlay(&self) -> SettingsOverlay {
        SettingsOverlay {
            landing: Some(LandingOverlay {
                enabled: Some(self.landing.enabled),
                title: Some(self.landing.title.clone().unwrap_or_default()),
                expose_version: Some(self.landing.expose_version),
                expose_chains: Some(self.landing.expose_chains),
                expose_price_feed: Some(self.landing.expose_price_feed),
                expose_uptime: Some(self.landing.expose_uptime),
                stats_enabled: Some(self.landing.stats_enabled),
                stats_cache_hours: Some(self.landing.stats_cache_hours),
            }),
            retention: Some(RetentionOverlay {
                login_events_days: Some(self.retention.login_events_days),
                audit_days: Some(self.retention.audit_days),
                erasure_enabled: Some(self.retention.erasure_enabled),
                purge_login_events: Some(self.retention.purge_login_events),
                export_per_day: Some(self.retention.export_per_day),
                grace_period_hours: Some(self.retention.grace_period_hours),
            }),
            restore: Some(RestoreOverlay {
                policy: Some(self.restore.policy.as_str().to_string()),
                max_depth_days: Some(self.restore.max_depth_days),
                pow_free_days: Some(self.restore.pow_free_days),
                pow_days_per_bit: Some(self.restore.pow_days_per_bit),
                pow_max_bits: Some(self.restore.pow_max_bits),
            }),
            console: Some(ConsoleOverlay {
                restart_apply_mode: Some(self.console.restart_apply_mode.as_str().to_string()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_parses_sparse_json_ignoring_absent_and_unknown_sections() {
        // Absent sections stay None; unknown sections are ignored (forward-compat).
        let ov: SettingsOverlay = serde_json::from_str(
            r#"{"restore":{"policy":"unlimited"},"future_section":{"x":1}}"#,
        )
        .expect("sparse overlay parses");
        assert!(ov.landing.is_none());
        assert!(ov.retention.is_none());
        assert_eq!(ov.restore.unwrap().policy.as_deref(), Some("unlimited"));
    }

    #[test]
    fn runtime_class_classifies_known_and_defaults_restart_for_unknown() {
        assert_eq!(runtime_class("landing", "enabled"), RuntimeClass::RuntimeSafe);
        assert_eq!(
            runtime_class("restore", "max_depth_days"),
            RuntimeClass::RuntimeSafe
        );
        // erasure_enabled gates a boot worker; unknown pairs default restart-required.
        assert_eq!(
            runtime_class("retention", "erasure_enabled"),
            RuntimeClass::RestartRequired
        );
        assert_eq!(
            runtime_class("console", "restart_apply_mode"),
            RuntimeClass::RuntimeSafe
        );
        assert_eq!(runtime_class("mystery", "field"), RuntimeClass::RestartRequired);
    }

    #[test]
    fn console_overlay_parses_restart_apply_mode() {
        let ov: SettingsOverlay =
            serde_json::from_str(r#"{"console":{"restart_apply_mode":"auto"}}"#).unwrap();
        assert_eq!(
            ov.console.unwrap().restart_apply_mode.as_deref(),
            Some("auto")
        );
    }

    #[test]
    fn every_editable_field_has_a_runtime_class() {
        // EDITABLE_FIELDS is the enumerable surface GET /admin/config annotates.
        for (section, field) in EDITABLE_FIELDS {
            let _ = runtime_class(section, field); // no panic / all covered
        }
        assert!(EDITABLE_FIELDS.iter().any(|(s, f)| *s == "console" && *f == "restart_apply_mode"));
    }
}
