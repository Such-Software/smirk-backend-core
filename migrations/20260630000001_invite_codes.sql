-- Operator-minted registration invite codes — one composable registration gate
-- (alongside PoW and, later, pay-to-register). v1 is single-use, operator-minted
-- via the `smirk-admin mint-invite` CLI; the schema leaves room for multi-use,
-- expiry, and referral without a breaking change.
--
-- Only sha256(code) is stored. The raw code is a bearer secret shown once at
-- mint time and never persisted, so a database leak is NOT a list of usable
-- codes — codes are >=128-bit random, so the hash is not brute-forceable and no
-- pepper is needed.
CREATE TABLE invite_codes (
    code_hash   TEXT PRIMARY KEY,                       -- hex sha256 of the raw code
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    label       TEXT,                                   -- optional operator note (batch / who-for)
    expires_at  TIMESTAMPTZ,                            -- NULL = never (reserved; v1 mints without expiry)
    used_at     TIMESTAMPTZ,                            -- NULL = unused (single-use)
    used_by     UUID REFERENCES users (id) ON DELETE SET NULL
);

-- Fast lookup of still-spendable codes (mint listing / future sweeps).
CREATE INDEX idx_invite_codes_unused ON invite_codes (created_at) WHERE used_at IS NULL;
