-- Tamper-evident audit log for privileged actions (operator §0.4).
--
-- Separate from user `audit_logs` (which keeps its enum action for high-volume
-- login traffic): this table is the LOW-VOLUME admin/setup/erasure trail, with a
-- free-text action and a hash chain. Each row's row_hash =
-- HMAC(ADMIN_KEY_INTEGRITY_SECRET, prev_hash || canonical(row)); prev_hash is the
-- previous row's row_hash (or a genesis constant). A DB-write attacker who edits,
-- deletes, or reorders a row breaks the chain, which a boot/doctor check detects.
-- Keyed by the integrity secret (separate from DATABASE_URL) so the chain is
-- tamper-EVIDENT against a DB-write attacker (forgeable only under host
-- compromise — defense-in-depth, not a guarantee).
--
-- actor_pubkey_prefix stores only a short prefix, never the full pubkey, so this
-- table does not encode the admin social graph.
CREATE TABLE admin_audit_logs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seq                 BIGINT NOT NULL UNIQUE,    -- monotonic order, assigned under a lock
    action              TEXT NOT NULL,             -- 'admin_login' | 'admin_key_added' | ...
    actor_kind          TEXT NOT NULL,             -- 'user' | 'admin' | 'cli' | 'bootstrap'
    actor_pubkey_prefix TEXT,                       -- first chars of the actor pubkey (no full key)
    target              TEXT,                       -- optional target id/pubkey
    details             JSONB,
    ip_address          INET,                       -- real TCP peer, never XFF
    created_at          TIMESTAMPTZ NOT NULL,
    prev_hash           TEXT NOT NULL,
    row_hash            TEXT NOT NULL
);

CREATE INDEX idx_admin_audit_logs_seq ON admin_audit_logs (seq);
CREATE INDEX idx_admin_audit_logs_action ON admin_audit_logs (action);
