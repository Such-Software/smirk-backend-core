# public-free — a free, open public instance

Anyone can register and use the wallet; spam is gated by proof-of-work, not
payment. This is the shape a free, open public instance runs.

- **Config:** [`.env.example`](.env.example) — `POW_REQUIRED=true`, no invite/payment
  gate, `WALLET_RESTORE_POLICY=bounded` + PoW-priced, relay off at launch.
- **Boot:** copy → `.env`, generate secrets, reuse your existing daemons / LWS, run
  the binary. Front it with TLS; bind the API to `127.0.0.1`.
- No money changes hands, so there is no payment/consumer-sale surface — just have a
  Terms + Privacy that disclose what the backend receives (see
  [`../LEGAL_AND_OPS.md`](../LEGAL_AND_OPS.md)).
