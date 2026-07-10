-- Social tips (PUBLIC-only): non-custodial share-URL tips.
--
-- A sender funds a tip address and publishes a claim URL whose fragment carries
-- the claim key; anyone holding the URL claims by sweeping the tip address to
-- their own wallet. The backend stores only the encrypted claim blob and a hash
-- of the claim key (for status tracking) — it never sees the claim key or the
-- funds.
--
-- Ported (public subset) from the legacy smirk-backend social_tips subsystem.
-- Targeted / @username tips and the socials + bot surface are intentionally
-- dropped: no recipient_* columns, no user_socials, no announcer.

-- Bump updated_at on every UPDATE. Self-contained: core defines no shared
-- updated_at trigger function of its own.
CREATE OR REPLACE FUNCTION social_tips_touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE social_tips (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    asset                       VARCHAR(8)  NOT NULL,   -- btc | ltc | xmr | wow
    amount                      BIGINT      NOT NULL,   -- smallest unit

    -- Public tip: anyone holding the claim URL can claim.
    is_public                   BOOLEAN     NOT NULL DEFAULT TRUE,
    claim_key_hash              VARCHAR(64),            -- SHA256(claim key); the key never touches the server
    encrypted_key               BYTEA,                  -- claim secret, encrypted; backend cannot decrypt

    -- Funding: the sender funds tip_address, which is swept to the claimer on claim.
    tip_address                 VARCHAR(255),
    funding_txid                VARCHAR(128),

    status                      VARCHAR(32) NOT NULL DEFAULT 'draft',

    -- Funding-confirmation tracking.
    funding_confirmations       INTEGER     NOT NULL DEFAULT 0,
    funding_confirmed_at        TIMESTAMPTZ,
    last_confirmation_check     TIMESTAMPTZ,
    confirmations_required      INTEGER     NOT NULL DEFAULT 0,

    -- Funding-amount verification: guards against a sender declaring more than
    -- they funded (the verifier only flips a tip claimable once the on-chain
    -- receipt covers `amount`).
    funding_amount_verified     BOOLEAN     NOT NULL DEFAULT FALSE,
    funding_amount_observed     BIGINT,
    funding_amount_verified_at  TIMESTAMPTZ,

    -- Claim.
    claimed_at                  TIMESTAMPTZ,
    claimed_by_user_id          UUID REFERENCES users(id) ON DELETE SET NULL,
    clawed_back_at              TIMESTAMPTZ,

    -- Sweep: a claim settles ('claimed') only once its sweep confirms on-chain.
    sweep_txid                  VARCHAR(128),
    sweep_confirmed_at          TIMESTAMPTZ,
    sweep_block_height          INTEGER,
    sweep_block_hash            TEXT,
    sweep_confirmed_dm_sent_at  TIMESTAMPTZ,            -- exactly-once notify stamp
    reorg_notified_at           TIMESTAMPTZ,            -- exactly-once reorg-notify stamp

    -- LWS (XMR/WOW): the tip address is registered with a view key so the backend
    -- can scan it for funding + sweep.
    tip_view_key                VARCHAR(64),
    lws_registered_at           TIMESTAMPTZ,
    lws_deactivated_at          TIMESTAMPTZ,

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Lifecycle:
    --   draft -> pending_confirmation -> pending -> claiming -> claimed
    --   draft -> cancelled
    --   pending_confirmation -> funding_mismatch (verifier saw a short receipt)
    --   {pending, pending_confirmation, claiming, funding_mismatch, cancelled} -> clawed_back
    CONSTRAINT social_tips_status_check CHECK (status IN (
        'draft',
        'pending_confirmation',
        'pending',
        'claiming',
        'claimed',
        'clawed_back',
        'cancelled',
        'funding_mismatch'
    )),
    -- Public tips must carry the claim-key hash.
    CONSTRAINT public_tip_has_hash CHECK (is_public = FALSE OR claim_key_hash IS NOT NULL)
);

CREATE INDEX idx_social_tips_sender ON social_tips(sender_user_id, created_at DESC);

CREATE INDEX idx_social_tips_claim_hash ON social_tips(claim_key_hash)
    WHERE claim_key_hash IS NOT NULL;

-- Confirmation poller: rows still awaiting funding confirmations.
CREATE INDEX idx_social_tips_pending_confirmation
    ON social_tips(asset, last_confirmation_check)
    WHERE status IN ('pending', 'pending_confirmation')
      AND confirmations_required > 0
      AND funding_confirmed_at IS NULL;

-- Amount verifier: confirmed-but-not-yet-amount-verified rows.
CREATE INDEX idx_social_tips_status_verified
    ON social_tips(status, funding_amount_verified)
    WHERE status IN ('pending', 'pending_confirmation', 'funding_mismatch');

-- Sweep reconciler + lifecycle GC: rows mid-claim.
CREATE INDEX idx_social_tips_claiming ON social_tips(status, updated_at)
    WHERE status = 'claiming';

CREATE TRIGGER social_tips_updated_at
    BEFORE UPDATE ON social_tips
    FOR EACH ROW EXECUTE FUNCTION social_tips_touch_updated_at();
