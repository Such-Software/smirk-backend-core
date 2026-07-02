# paid-relay — free wallet, paid Nostr posting (the flagship)

A free wallet (open + PoW) **plus** a paid premium tier for **general** Nostr
posting to your relay. Wallet-functional events — encrypted DMs, tips, swap
coordination — stay **free** for registered users; premium unlocks general posting.
Recurring revenue tied to a real service. Implements the
[premium-relay feature](../../docs/design/premium-relay.md).

- **Config:** [`.env.example`](.env.example) — `RELAY_WRITE_POLICY=premium-post`,
  `PREMIUM_ENABLED=true`, tiered `PREMIUM_PLANS` (a built-in discount curve), and the
  `PAYMENT_*` processor block (reused from pay-to-register; BTCPay-compatible).
- **Free vs paid:** the relay is free for what makes the wallet work; you pay to use
  it as your everyday relay. Reads stay open (v1); premium gates *writes*.
- **Money:** you sell access to your relay (a fee), non-custodial + pull-model —
  never hold funds. `PAYMENT_CONFIRMATIONS >= 1`; validation rejects the unsafe combos.
- **Content:** running a relay means hosting user content — a DMCA designated agent,
  a CSAM-reporting process, and acceptable-use terms apply. See
  [`../LEGAL_AND_OPS.md`](../LEGAL_AND_OPS.md).
- **Resources:** the relay runs beside the wallet backend + LWS, so keep the size /
  retention / connection / rate caps (in `.env.example` and the nostr-rs-relay config
  under `deploy/relay`); move to `RELAY_MODE=external` on its own host if load climbs.
