-- Premium tier: recurring, tiered access to the operator's Nostr relay for
-- general posting (the `premium-post` write policy). Wallet-functional events
-- stay free; premium unlocks general Nostr publishing.
--
-- `premium_until` is the subscription expiry (NULL = never premium). No index: the
-- hot check (is_premium_npub) is served by the existing UNIQUE index on
-- users.nostr_pubkey, and the `premium_until > NOW()` predicate is a cheap per-row
-- filter — a standalone index would only add write cost to every users UPDATE.
ALTER TABLE users ADD COLUMN premium_until TIMESTAMPTZ;

-- Mirrors payment_invoices, but binds on the authenticated user_id (a logged-in
-- premium purchase) and carries the plan's period. Single-use on redemption,
-- same atomic consume pattern. Only public data — never funds or keys.
CREATE TABLE premium_invoices (
    invoice_id  TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    plan_id     TEXT NOT NULL,
    period_days INTEGER NOT NULL,
    amount      TEXT NOT NULL,
    currency    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ
);
CREATE INDEX premium_invoices_unconsumed_idx
    ON premium_invoices (user_id) WHERE consumed_at IS NULL;
