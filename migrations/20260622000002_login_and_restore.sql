-- Login analytics + restore-attempt abuse tracking.
--
-- Both tables store only keyed hashes of sensitive values: login_events.ip_hash
-- and restore_attempts.ip_hash are salted IP hashes; restore_attempts.fingerprint
-- is a peppered HMAC of the seed fingerprint. No raw IPs or reproducible
-- fingerprints are stored.

CREATE TABLE login_events (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    asset      TEXT NOT NULL,        -- login method/asset (btc, ..., nostr, extension)
    platform   TEXT NOT NULL,        -- extension | web | nostr
    origin     TEXT,
    ip_hash    TEXT,                 -- salted hash of the client IP
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_login_events_created_at ON login_events (created_at);
CREATE INDEX idx_login_events_user_id ON login_events (user_id);
-- Covering index for the (asset, platform) GROUP BY aggregations.
CREATE INDEX idx_login_events_asset_platform ON login_events (asset, platform, created_at);

CREATE TABLE restore_attempts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint TEXT NOT NULL,       -- peppered HMAC of the seed fingerprint
    ip_hash     TEXT,                -- salted hash of the client IP
    success     BOOLEAN NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_restore_attempts_fingerprint ON restore_attempts (fingerprint, created_at);
CREATE INDEX idx_restore_attempts_ip_hash ON restore_attempts (ip_hash, created_at);
CREATE INDEX idx_restore_attempts_created_at ON restore_attempts (created_at);
