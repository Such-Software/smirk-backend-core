# paid-access — a paid hosted wallet backend

A one-time fee gates creating a NEW wallet (existing wallets and self-hosters bypass
it). Non-custodial and pull-model: the backend only reads invoice status, and funds
go straight to your own wallet.

- **Config:** [`.env.example`](.env.example) — `REGISTRATION_REQUIRE_PAYMENT=true` +
  the `PAYMENT_*` processor block (BTCPay-compatible; also served by xmrcheckout /
  wowcheckout). Price is fiat-denominated, payable in any coin the processor offers.
- **You are a merchant, not a money transmitter** — you sell access to your service
  and never hold user funds. Have clear Terms (what the fee buys, refunds, fair use),
  treat the fees as income, and see [`../LEGAL_AND_OPS.md`](../LEGAL_AND_OPS.md).
- `PAYMENT_CONFIRMATIONS >= 1` (0-conf lets a paid invoice be reversed after signup).
