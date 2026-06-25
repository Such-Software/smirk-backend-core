-- Unified server-nonce (challenge) store for signed actions.
--
-- One mechanism for every server-issued single-use nonce — admin login, first-run
-- setup, and self-service erasure — consumed atomically so a nonce can be used at
-- most once even across concurrent requests / fleet nodes:
--   DELETE FROM challenges WHERE nonce=$1 AND purpose=$2 AND expires_at > NOW()
--                          RETURNING subject;
-- Winning the race returns exactly one row; zero rows = replay/expired ⇒ reject.
-- This is the DB-backed variant (correct under a shared database and a future
-- load-balanced fleet); it carries no long-lived secret.
--
-- Operational note: this table is ephemeral (it links "pubkey acted at time T")
-- and should be EXCLUDED from backups.
CREATE TABLE challenges (
    nonce      TEXT PRIMARY KEY,            -- 32 random bytes, hex
    purpose    TEXT NOT NULL,               -- 'admin_login' | 'setup' | 'erasure_request' | ...
    subject    TEXT,                        -- optional bound subject (e.g. target pubkey/id)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Supports the periodic expiry sweep (the consume query is keyed by the PK).
CREATE INDEX idx_challenges_expires_at ON challenges (expires_at);
