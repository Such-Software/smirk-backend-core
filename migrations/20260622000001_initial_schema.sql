-- Initial schema for smirk-backend-core.
--
-- Nostr-native identity: a user is keyed by pubkey_hash (peppered), an optional
-- nostr_pubkey, and an optional reserved username. No platform-login columns.
-- pubkey_hash and seed_fingerprint are stored HMAC-peppered (the pepper lives in
-- config); UNIQUE constraints are on the peppered values. FK ON DELETE clauses
-- support self-service erasure. Requires PostgreSQL 13+ (gen_random_uuid).

-- ── Enum types ──────────────────────────────────────────────────────────────
CREATE TYPE asset_type AS ENUM ('btc', 'ltc', 'xmr', 'wow', 'grin');

CREATE TYPE slatepack_status AS ENUM (
    'pending_recipient', 'pending_sender', 'finalized', 'expired', 'cancelled'
);

CREATE TYPE audit_action AS ENUM (
    'user_created', 'user_login', 'wallet_created', 'wallet_registered',
    'tx_broadcast', 'session_created', 'session_revoked'
);

-- ── users ───────────────────────────────────────────────────────────────────
CREATE TABLE users (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username         TEXT UNIQUE,
    pubkey_hash      TEXT UNIQUE,            -- peppered at rest
    nostr_pubkey     TEXT UNIQUE,
    wallet_birthday  TIMESTAMPTZ,
    seed_fingerprint TEXT UNIQUE,            -- peppered at rest
    xmr_start_height BIGINT,
    wow_start_height BIGINT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ
);
-- UNIQUE constraints already index username/pubkey_hash/nostr_pubkey/seed_fingerprint.

-- ── wallets ─────────────────────────────────────────────────────────────────
CREATE TABLE wallets (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    asset                asset_type NOT NULL,
    address              TEXT NOT NULL,
    view_key             TEXT,
    derivation_index     INTEGER,
    registered_with_node BOOLEAN NOT NULL DEFAULT FALSE,
    registration_error   TEXT,
    label                TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_wallets_user_id ON wallets (user_id);
CREATE INDEX idx_wallets_address ON wallets (address);

-- ── sessions ────────────────────────────────────────────────────────────────
CREATE TABLE sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL,        -- peppered at rest
    platform           TEXT NOT NULL,        -- extension | web | nostr
    device_info        TEXT,
    ip_address         INET,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    last_used_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_refresh_token_hash ON sessions (refresh_token_hash);

-- ── user_keys ───────────────────────────────────────────────────────────────
CREATE TABLE user_keys (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    asset            asset_type NOT NULL,
    public_key       TEXT NOT NULL,
    public_spend_key TEXT,
    key_type         TEXT NOT NULL DEFAULT 'primary',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, asset, key_type)
);
CREATE INDEX idx_user_keys_user_id ON user_keys (user_id);

-- ── grin_slatepacks ─────────────────────────────────────────────────────────
CREATE TABLE grin_slatepacks (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- UNIQUE: the relay's authorization + state machine key off slate_id, so it
    -- must map to exactly one row (a collision would let mutations keyed on
    -- slate_id touch another user's relay). Also serves as the lookup index.
    slate_id          TEXT NOT NULL UNIQUE,
    sender_user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    recipient_address TEXT,
    slatepack_content TEXT NOT NULL,
    amount_nanogrin   BIGINT NOT NULL,
    status            slatepack_status NOT NULL DEFAULT 'pending_recipient',
    response_slatepack TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,
    finalized_at      TIMESTAMPTZ,
    tx_hash           TEXT
);
-- (slate_id lookup index is provided by the UNIQUE constraint above.)
CREATE INDEX idx_grin_slatepacks_sender ON grin_slatepacks (sender_user_id);
CREATE INDEX idx_grin_slatepacks_recipient ON grin_slatepacks (recipient_user_id);
CREATE INDEX idx_grin_slatepacks_status ON grin_slatepacks (status);

-- ── audit_logs ──────────────────────────────────────────────────────────────
CREATE TABLE audit_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    action        audit_action NOT NULL,
    resource_type TEXT,
    resource_id   UUID,
    details       JSONB,
    ip_address    INET,
    user_agent    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs (action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at);
