-- Operator-editable settings overlay: the DB precedence tier UNDER the env-derived
-- Config (effective = defaults -> env -> DB overlay). One JSONB row per section; the
-- effective Config is rebuilt from these at boot and on change. Each row is MAC'd with
-- ADMIN_KEY_INTEGRITY_SECRET (same anchor as server_config / admin_keys) so a DB-write
-- attacker cannot silently flip operator policy, and every write is appended to the
-- hash-chained admin_audit log. A missing section = env-only (no seed rows). Secrets are
-- NEVER stored here (overlays carry no secret fields by construction).
CREATE TABLE operator_settings (
    section       TEXT PRIMARY KEY,
    doc           JSONB NOT NULL,
    version       BIGINT NOT NULL DEFAULT 1,
    updated_by    UUID REFERENCES admin_keys(id) ON DELETE SET NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    integrity_mac TEXT NOT NULL
);
