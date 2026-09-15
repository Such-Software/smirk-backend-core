-- Split the Grin slatepack address out of the `primary` key row.
--
-- A v0.3.0 wallet registers two DIFFERENT Grin keys in sequence. Bootstrap
-- (`/auth/extension`) stores the Smirk-derived pubkey, hex, which is what
-- `/auth/website/verify` checks a Grin signature against. A deferred effect then
-- re-registers the canonical grin-wallet slatepack address, which is a separate
-- derivation, not another encoding of the same key. Both wrote
-- `(user_id, 'grin', 'primary')`, so the second silently replaced the first and
-- website sign-in with Grin stopped matching any account.
--
-- The slatepack address now gets its own `slatepack` row, so both values coexist:
-- sign-in reads `primary`, senders read `slatepack`, and the address -> user
-- lookup matches either because it does not filter on key_type.
--
-- Additive on purpose. Existing bech32 values are COPIED across and the `primary`
-- row is left in place, to be rewritten with the hex pubkey by the next unlock.
-- Nothing is deleted, so a user who never unlocks again keeps working discovery
-- instead of losing their address to a migration.
INSERT INTO user_keys (user_id, asset, public_key, public_spend_key, key_type)
SELECT user_id, asset, public_key, public_spend_key, 'slatepack'
FROM user_keys
WHERE asset = 'grin'
  AND key_type = 'primary'
  AND (public_key LIKE 'grin1%' OR public_key LIKE 'tgrin1%')
ON CONFLICT (user_id, asset, key_type) DO NOTHING;
