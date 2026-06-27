-- First-run bootstrap latch (operator §3.2).
--
-- Bootstrap mode is NOT derived from "no active admin keys" — it is an explicit,
-- MAC-protected latch, so a DB-write attacker who restores a pre-bootstrap backup
-- (or flips the state) to re-open trust-on-first-use produces a MAC mismatch the
-- server detects and fails closed on. The MAC is keyed by the same
-- ADMIN_KEY_INTEGRITY_SECRET as admin_keys, over setup_state|bootstrap_completed_at.
-- Singleton row (id = 1).
CREATE TABLE server_config (
    id                     INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    setup_state            TEXT NOT NULL DEFAULT 'uninitialized', -- uninitialized | locked
    bootstrap_completed_at TIMESTAMPTZ,
    locked_at              TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    integrity_mac          TEXT NOT NULL
);
