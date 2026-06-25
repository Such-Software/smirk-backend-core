-- Admin authentication & authorization (operator §0.3 / §1.2).
--
-- The server stores ONLY public keys — an admin proves control of a private key
-- (NIP-98 signed action) and is authorized by presence in this allowlist. Each
-- row carries an integrity MAC keyed by ADMIN_KEY_INTEGRITY_SECRET (separate from
-- DATABASE_URL): it covers id|pubkey|scope|created_at|activated_at|revoked_at, so
-- a DB-write attacker who flips revoked_at back to NULL (un-revoke) or revives a
-- key produces a MAC mismatch that the guard rejects. Revocation is a soft
-- revoke (the audit trail survives); the partial unique index keeps at most one
-- ACTIVE row per pubkey while allowing historical revoked rows.
CREATE TABLE admin_keys (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pubkey              TEXT NOT NULL,            -- x-only secp256k1 hex, 64 lowercase
    label               TEXT,
    scope               TEXT NOT NULL DEFAULT 'admin',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by_kind     TEXT NOT NULL,            -- 'admin' | 'cli' | 'bootstrap' (coarse; no social graph)
    activated_at        TIMESTAMPTZ,              -- NULL = pending (first login not yet completed)
    activation_deadline TIMESTAMPTZ,              -- pending key auto-expires after this
    revoked_at          TIMESTAMPTZ,              -- soft revoke
    last_used_at        TIMESTAMPTZ,
    integrity_mac       TEXT NOT NULL             -- HMAC(integrity_secret, id|pubkey|scope|created_at|activated_at|revoked_at)
);

-- At most one ACTIVE allowlist entry per pubkey; revoked rows are unconstrained.
CREATE UNIQUE INDEX admin_keys_active_pubkey ON admin_keys (pubkey) WHERE revoked_at IS NULL;

-- Admin sessions are a SEPARATE table from user `sessions` (cryptographically
-- distinct tokens, distinct secret). Revoking the key cascades to its sessions.
CREATE TABLE admin_sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_key_id       UUID NOT NULL REFERENCES admin_keys (id) ON DELETE CASCADE,
    pubkey             TEXT NOT NULL,
    refresh_token_hash TEXT NOT NULL,             -- peppered at rest (never the token)
    access_jti         TEXT NOT NULL,             -- the live access token's id
    device_info        TEXT,
    ip_address         INET,                      -- real TCP peer, never XFF
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ
);

CREATE INDEX idx_admin_sessions_key ON admin_sessions (admin_key_id);
CREATE INDEX idx_admin_sessions_jti ON admin_sessions (access_jti) WHERE revoked_at IS NULL;
