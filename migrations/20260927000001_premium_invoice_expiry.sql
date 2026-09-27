-- Expired checkout windows must release pending-invoice slots. Retain rows so
-- an invoice paid before expiry can still be redeemed after confirmations.
ALTER TABLE premium_invoices ADD COLUMN expires_at TIMESTAMPTZ;
-- Historical rows did not record their lifetime. Seven days is the maximum
-- allowed by the existing configuration, so this cannot free a live slot early.
UPDATE premium_invoices SET expires_at = created_at + INTERVAL '7 days';
ALTER TABLE premium_invoices ALTER COLUMN expires_at SET NOT NULL;
CREATE INDEX premium_invoices_pending_expiry_idx
    ON premium_invoices (user_id, expires_at) WHERE consumed_at IS NULL;
