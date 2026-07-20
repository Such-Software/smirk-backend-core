//! Operator-editable settings overlay — the DB precedence tier under the env-derived
//! [`Config`] (effective = defaults -> env -> DB overlay). A [`SettingsOverlay`] is a
//! SPARSE patch: one `Option<*Overlay>` per editable section, each a struct of
//! `Option<T>` NON-SECRET fields (absent = "leave as env"). Secrets are excluded BY
//! CONSTRUCTION — no overlay field maps to a secret sub-struct — so the admin plane can
//! neither read nor set one. [`Config::apply_overlay`] merges an overlay onto the
//! env-derived config and re-runs the SAME [`Config::validate`] boot uses, so a bad edit
//! fails identically and nothing invalid is ever applied. Pure over `Config`.

use serde::{Deserialize, Serialize};

use crate::config::{Config, GateMode, RestartApplyMode, RestorePolicy};
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
    pub registration: Option<RegistrationOverlay>,
    pub pow: Option<PowOverlay>,
    pub features: Option<FeaturesOverlay>,
    pub relay: Option<RelayOverlay>,
    pub premium: Option<PremiumOverlay>,
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

/// Registration gating POLICY knobs. Most are read per-request → runtime-safe; the
/// exception is `require_payment`, which gates the boot-built payment client and is
/// therefore restart-required (see `runtime_class`). The processor WIRING (provider,
/// provider_url, store_id) and the SECRET api_key stay in env by design: they pair
/// with the secret and are set-once infra, so they are deliberately absent here.
/// Toggling `require_payment` on with incomplete wiring is rejected by
/// `Config::validate` at PUT time (fail-closed).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistrationOverlay {
    pub require_invite: Option<bool>,
    /// `all` (every enabled gate) | `any` (one-of). PoW is orthogonal.
    pub gate_mode: Option<String>,
    pub require_payment: Option<bool>,
    /// Registration price as a decimal string (no float math).
    pub payment_amount: Option<String>,
    pub payment_currency: Option<String>,
    pub payment_confirmations: Option<u32>,
    pub payment_expires_minutes: Option<u32>,
}

/// Proof-of-work signup gate (read per-request → runtime-safe). The HMAC key is a
/// SECRET and stays in env; enabling the gate without it is rejected by validate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PowOverlay {
    pub enabled: Option<bool>,
    pub required: Option<bool>,
    pub cost: Option<u64>,
}

/// Feature flags + per-chain enablement. Each gates a boot-built client or worker
/// (price poller, chain adapters), so these are RESTART-REQUIRED. Enabling a chain
/// with no infra configured is rejected in production by validate (fail-closed).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FeaturesOverlay {
    pub prices: Option<bool>,
    pub prices_provider: Option<String>,
    pub prices_interval_secs: Option<u64>,
    pub prices_currency: Option<String>,
    pub tips: Option<bool>,
    pub nostr_identity: Option<bool>,
    pub grin_relay: Option<bool>,
    pub chain_btc: Option<bool>,
    pub chain_ltc: Option<bool>,
    pub chain_xmr: Option<bool>,
    pub chain_wow: Option<bool>,
    pub chain_grin: Option<bool>,
}

/// Nostr relay NON-BIND, non-secret scalars. The admission-service BIND address
/// (a registration oracle) and the write-allowlist (a list) are deliberately
/// absent — bind is security-load-bearing and stays in env. RESTART-REQUIRED (the
/// relay/admission service is boot-bound and the URL is advertised at boot).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayOverlay {
    pub enabled: Option<bool>,
    /// `bundled` | `external`.
    pub mode: Option<String>,
    /// Public `ws(s)://` URL clients connect to + we advertise.
    pub advertised_url: Option<String>,
    /// `inbox-outbox` | `author-allowlist` | `open` | `premium-post`.
    pub write_policy: Option<String>,
    pub inbound_pow_bits: Option<u8>,
    pub max_event_bytes: Option<usize>,
    pub retention_days: Option<u32>,
}

/// Premium subscription master switch + currency. The priced PLANS are a list and
/// stay env-configured until a structured list editor exists. RESTART-REQUIRED
/// (premium is enforced by the boot-bound relay admission service).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PremiumOverlay {
    pub enabled: Option<bool>,
    pub currency: Option<String>,
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
        // require_payment gates the BOOT-built payment client (main.rs: the provider is
        // None unless require_payment || premium.enabled at boot), so hot-enabling it
        // would 500 every registration until restart — restart-required, like premium.
        ("registration", "require_payment") => RestartRequired,
        // The other registration gates + PoW are read via `state.cfg()` on the
        // registration path (auth.rs / capabilities.rs), so an overlay change lands on
        // the next request — hot-swappable. (payment_amount/currency/etc. are read per
        // invoice; they only matter once the boot-built client exists.)
        ("registration", _) => RuntimeSafe,
        ("pow", _) => RuntimeSafe,
        // Feature flags / chain enablement / relay / premium all gate boot-built
        // clients, workers, or the boot-bound admission service — a live flip would
        // desync the running process, so they apply on a graceful restart.
        ("features", _) => RestartRequired,
        ("relay", _) => RestartRequired,
        ("premium", _) => RestartRequired,
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

        if let Some(rg) = &ov.registration {
            if let Some(v) = rg.require_invite {
                c.registration.require_invite = v;
            }
            if let Some(m) = &rg.gate_mode {
                // GateMode maps to a Rust enum, and env parsing is lenient (unknown
                // -> All); a console PUT should reject a typo instead of silently
                // weakening the gate, so match strictly here.
                c.registration.gate_mode = match m.to_lowercase().as_str() {
                    "all" => GateMode::All,
                    "any" => GateMode::Any,
                    other => {
                        return Err(AppError::ValidationError(format!(
                            "invalid registration.gate_mode {other:?} (want all|any)"
                        )))
                    }
                };
            }
            if let Some(v) = rg.require_payment {
                c.registration.payment.require_payment = v;
            }
            if let Some(v) = &rg.payment_amount {
                c.registration.payment.amount = v.clone();
            }
            if let Some(v) = &rg.payment_currency {
                // Match env normalization (`.to_uppercase()`).
                c.registration.payment.currency = v.to_uppercase();
            }
            if let Some(v) = rg.payment_confirmations {
                c.registration.payment.confirmations = v;
            }
            if let Some(v) = rg.payment_expires_minutes {
                c.registration.payment.expires_minutes = v;
            }
        }

        if let Some(p) = &ov.pow {
            if let Some(v) = p.enabled {
                c.pow.enabled = v;
            }
            if let Some(v) = p.required {
                c.pow.required = v;
            }
            if let Some(v) = p.cost {
                c.pow.cost = v;
            }
        }

        if let Some(f) = &ov.features {
            if let Some(v) = f.prices {
                c.features.prices = v;
            }
            if let Some(v) = &f.prices_provider {
                c.features.prices_provider = v.to_lowercase();
            }
            if let Some(v) = f.prices_interval_secs {
                c.features.prices_interval_secs = v;
            }
            if let Some(v) = &f.prices_currency {
                c.features.prices_currency = v.to_lowercase();
            }
            if let Some(v) = f.tips {
                c.features.tips = v;
            }
            if let Some(v) = f.nostr_identity {
                c.features.nostr_identity = v;
            }
            if let Some(v) = f.grin_relay {
                c.features.grin_relay = v;
            }
            if let Some(v) = f.chain_btc {
                c.features.chains.btc = v;
            }
            if let Some(v) = f.chain_ltc {
                c.features.chains.ltc = v;
            }
            if let Some(v) = f.chain_xmr {
                c.features.chains.xmr = v;
            }
            if let Some(v) = f.chain_wow {
                c.features.chains.wow = v;
            }
            if let Some(v) = f.chain_grin {
                c.features.chains.grin = v;
            }
        }

        if let Some(r) = &ov.relay {
            if let Some(v) = r.enabled {
                c.messaging.relay.enabled = v;
            }
            if let Some(v) = &r.mode {
                c.messaging.relay.mode = v.to_lowercase();
            }
            if let Some(v) = &r.advertised_url {
                c.messaging.relay.advertised_url = v.clone();
            }
            if let Some(v) = &r.write_policy {
                c.messaging.relay.write_policy = v.to_lowercase();
            }
            if let Some(v) = r.inbound_pow_bits {
                c.messaging.relay.inbound_pow_bits = v;
            }
            if let Some(v) = r.max_event_bytes {
                c.messaging.relay.max_event_bytes = v;
            }
            if let Some(v) = r.retention_days {
                c.messaging.relay.retention_days = v;
            }
        }

        if let Some(pr) = &ov.premium {
            if let Some(v) = pr.enabled {
                c.premium.enabled = v;
            }
            if let Some(v) = &pr.currency {
                c.premium.currency = v.to_uppercase();
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
    ("registration", "require_invite"),
    ("registration", "gate_mode"),
    ("registration", "require_payment"),
    ("registration", "payment_amount"),
    ("registration", "payment_currency"),
    ("registration", "payment_confirmations"),
    ("registration", "payment_expires_minutes"),
    ("pow", "enabled"),
    ("pow", "required"),
    ("pow", "cost"),
    ("features", "prices"),
    ("features", "prices_provider"),
    ("features", "prices_interval_secs"),
    ("features", "prices_currency"),
    ("features", "tips"),
    ("features", "nostr_identity"),
    ("features", "grin_relay"),
    ("features", "chain_btc"),
    ("features", "chain_ltc"),
    ("features", "chain_xmr"),
    ("features", "chain_wow"),
    ("features", "chain_grin"),
    ("relay", "enabled"),
    ("relay", "mode"),
    ("relay", "advertised_url"),
    ("relay", "write_policy"),
    ("relay", "inbound_pow_bits"),
    ("relay", "max_event_bytes"),
    ("relay", "retention_days"),
    ("premium", "enabled"),
    ("premium", "currency"),
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
            registration: Some(RegistrationOverlay {
                require_invite: Some(self.registration.require_invite),
                gate_mode: Some(self.registration.gate_mode.as_str().to_string()),
                require_payment: Some(self.registration.payment.require_payment),
                payment_amount: Some(self.registration.payment.amount.clone()),
                payment_currency: Some(self.registration.payment.currency.clone()),
                payment_confirmations: Some(self.registration.payment.confirmations),
                payment_expires_minutes: Some(self.registration.payment.expires_minutes),
            }),
            pow: Some(PowOverlay {
                enabled: Some(self.pow.enabled),
                required: Some(self.pow.required),
                cost: Some(self.pow.cost),
            }),
            features: Some(FeaturesOverlay {
                prices: Some(self.features.prices),
                prices_provider: Some(self.features.prices_provider.clone()),
                prices_interval_secs: Some(self.features.prices_interval_secs),
                prices_currency: Some(self.features.prices_currency.clone()),
                tips: Some(self.features.tips),
                nostr_identity: Some(self.features.nostr_identity),
                grin_relay: Some(self.features.grin_relay),
                chain_btc: Some(self.features.chains.btc),
                chain_ltc: Some(self.features.chains.ltc),
                chain_xmr: Some(self.features.chains.xmr),
                chain_wow: Some(self.features.chains.wow),
                chain_grin: Some(self.features.chains.grin),
            }),
            relay: Some(RelayOverlay {
                enabled: Some(self.messaging.relay.enabled),
                mode: Some(self.messaging.relay.mode.clone()),
                advertised_url: Some(self.messaging.relay.advertised_url.clone()),
                write_policy: Some(self.messaging.relay.write_policy.clone()),
                inbound_pow_bits: Some(self.messaging.relay.inbound_pow_bits),
                max_event_bytes: Some(self.messaging.relay.max_event_bytes),
                retention_days: Some(self.messaging.relay.retention_days),
            }),
            premium: Some(PremiumOverlay {
                enabled: Some(self.premium.enabled),
                currency: Some(self.premium.currency.clone()),
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
        let ov: SettingsOverlay =
            serde_json::from_str(r#"{"restore":{"policy":"unlimited"},"future_section":{"x":1}}"#)
                .expect("sparse overlay parses");
        assert!(ov.landing.is_none());
        assert!(ov.retention.is_none());
        assert_eq!(ov.restore.unwrap().policy.as_deref(), Some("unlimited"));
    }

    #[test]
    fn runtime_class_classifies_known_and_defaults_restart_for_unknown() {
        assert_eq!(
            runtime_class("landing", "enabled"),
            RuntimeClass::RuntimeSafe
        );
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
        // require_payment gates the boot-built payment client -> restart-required,
        // while its sibling registration gates hot-swap.
        assert_eq!(
            runtime_class("registration", "require_payment"),
            RuntimeClass::RestartRequired
        );
        assert_eq!(
            runtime_class("registration", "require_invite"),
            RuntimeClass::RuntimeSafe
        );
        assert_eq!(
            runtime_class("mystery", "field"),
            RuntimeClass::RestartRequired
        );
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
        assert!(EDITABLE_FIELDS
            .iter()
            .any(|(s, f)| *s == "console" && *f == "restart_apply_mode"));
    }
}
