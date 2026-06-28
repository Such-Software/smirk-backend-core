-- Self-service erasure requests (operator §5.3).
--
-- Two-phase (request -> confirm) with a grace window before execution. The row
-- is keyed by user_id while live (execution needs it), but ON DELETE SET NULL so
-- the COMPLETED tombstone survives the user delete with the link scrubbed.
-- subject_hash is sha256(npub) — an opaque tombstone id, never the raw npub.
CREATE TABLE erasure_requests (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID REFERENCES users (id) ON DELETE SET NULL,
    subject_hash   TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending', -- pending | confirmed | completed | cancelled
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scheduled_for  TIMESTAMPTZ NOT NULL,
    confirmed_at   TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ,
    cancelled_at   TIMESTAMPTZ
);

-- At most one live (pending/confirmed) request per user.
CREATE UNIQUE INDEX erasure_requests_active_user
    ON erasure_requests (user_id) WHERE status IN ('pending', 'confirmed');

-- Drives the execution sweeper.
CREATE INDEX idx_erasure_requests_due
    ON erasure_requests (scheduled_for) WHERE status = 'confirmed';
