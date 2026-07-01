-- Pay-to-register: a per-registration payment invoice created via an external,
-- non-custodial payment processor (the BTCPay-compatible adapter covers this
-- project's own xmrcheckout/wowcheckout apps, BTCPay Server, and its Monero
-- plugin). One composable registration gate alongside PoW and invite codes.
--
-- The backend is a THIN client: it creates the invoice on the operator's
-- processor, binds it here to the registrant's `pubkey_hash`, and — in the pull
-- model — grants the registration only after reading `Settled` from the
-- processor's authenticated API and ATOMICALLY consuming this row (single-use).
--
-- No funds and no view/spend keys ever touch this table: only the processor's
-- opaque invoice id, the identity the invoice is bound to, and the price we
-- asked for. The payer pays the OPERATOR's own wallet directly (view-only
-- detection on the processor side), so this stays non-custodial like every other
-- chain path. Self-hosting bypasses the gate entirely (leave the gate off).
--
-- `invoice_id` is the processor's id, NOT attacker-chosen; the row is the
-- binding authority (the processor-side metadata bind is only defense-in-depth).
CREATE TABLE payment_invoices (
    invoice_id   TEXT PRIMARY KEY,                       -- processor's opaque invoice id
    pubkey_hash  TEXT NOT NULL,                          -- registrant identity bound to it (hex sha256 of the BTC pubkey)
    provider     TEXT NOT NULL,                          -- adapter kind that minted it (e.g. 'btcpay')
    amount       TEXT NOT NULL,                          -- operator-configured price, as a decimal string (no float math)
    currency     TEXT NOT NULL,                          -- price currency ('XMR', or a fiat code the processor converts)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at  TIMESTAMPTZ                             -- NULL = unspent; set once, atomically, when it grants a registration
);

-- Binding lookup on completion: a registrant's still-unspent invoices.
CREATE INDEX idx_payment_invoices_unspent ON payment_invoices (pubkey_hash) WHERE consumed_at IS NULL;
