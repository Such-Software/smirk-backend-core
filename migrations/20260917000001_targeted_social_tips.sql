-- Targeted social tips: a tip addressed to a Smirk user rather than to whoever
-- holds a share URL.
--
-- The v3 port shipped public-only and the table says so: there is no recipient
-- anywhere, so a targeted tip had no one to be addressed to and the create path
-- rejected it outright. This adds the missing column and the two constraints
-- that keep each kind of tip well formed.
--
-- Additive and reversible in practice: every existing row is public, so the new
-- column is NULL for all of them and the new CHECK is satisfied by is_public.
-- Nothing is dropped, rewritten or backfilled.

ALTER TABLE social_tips
    ADD COLUMN IF NOT EXISTS recipient_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- A targeted tip must name its recipient. The mirror of public_tip_has_hash:
-- between them, every row carries whichever claim path it actually uses, and a
-- row that carries neither cannot be inserted.
ALTER TABLE social_tips
    DROP CONSTRAINT IF EXISTS targeted_tip_has_recipient;
ALTER TABLE social_tips
    ADD CONSTRAINT targeted_tip_has_recipient
    CHECK (is_public = TRUE OR recipient_user_id IS NOT NULL);

-- A targeted tip's ciphertext is sealed to the recipient's key and there is no
-- URL fragment, so encrypted_key is the only way to claim it. Without this a
-- draft could be created that is permanently unclaimable while looking healthy.
ALTER TABLE social_tips
    DROP CONSTRAINT IF EXISTS targeted_tip_has_encrypted_key;
ALTER TABLE social_tips
    ADD CONSTRAINT targeted_tip_has_encrypted_key
    CHECK (is_public = TRUE OR encrypted_key IS NOT NULL);

-- The inbox query: a recipient's tips, newest first.
CREATE INDEX IF NOT EXISTS idx_social_tips_recipient
    ON social_tips (recipient_user_id, created_at DESC)
    WHERE recipient_user_id IS NOT NULL;
