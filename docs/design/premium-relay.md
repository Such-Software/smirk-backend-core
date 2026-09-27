# Premium relay access

> Status: stable · Updated 2026-09-27 · Applies to: backend v0.3.0 source

Premium buys a prepaid period of general posting on this instance's Nostr relay.
It does not grant custody, change wallet balances, or charge a user automatically.
The feature defaults off. Plans and payment methods come from the configured
instance, so examples here are not production pricing or deployment evidence.

## Access policy

`RELAY_WRITE_POLICY=premium-post` admits registered users' wallet events for free:
NIP-59 gift wraps (kind 1059, including encrypted messages and tip payloads) and
NIP-17 relay lists (kind 10050). Active premium permits other Nostr event kinds.
The operator's explicit write allowlist also permits general posting; a note on
the feed therefore does not prove that its author paid for premium.

External authors may deliver gift wraps to registered recipients, subject to the
configured proof of work. Reads remain open. Other public relays apply their own
policies. Wallet registration can have independently configured gates; premium
does not determine those gates.

The authority is `src/infra/relay/policy.rs`, called by the relay admission service.
The wallet uses `/premium/status` to display the server's `can_post_general`
decision. A client display is never sufficient authorization to publish.

## Purchase and renewal

1. The authenticated client selects a plan and optional payment rail from
   `/capabilities`, then posts `{plan, rail}` to `/premium/invoice`.
2. The backend mints an invoice for the server-configured price and period. It
   records the user, processor, amount, currency, period and payment-window expiry.
3. The user pays at the returned checkout URL. The client calls
   `/premium/activate` with the invoice ID after payment.
4. The backend queries the processor that minted that invoice. A settled payment
   bound to this user can be consumed once. Consumption and extending
   `premium_until` occur in one database transaction.

Early renewal extends from the later of the current expiry and now. A consumed
invoice cannot extend the period twice. Disabling a payment rail leaves existing
invoice bindings intact; activation refuses until that rail is available again.

The backend limits unconsumed invoices whose payment windows remain open. Expired
windows release capacity, but their rows remain so a paid invoice can still be
redeemed after confirmation. Existing rows created before expiry was recorded
receive the previous maximum window of seven days in the additive migration.

## Payment requirements

The primary rail uses BTCPay's Greenfield API. Additional `xmrcheckout` and
`wowcheckout` rails use compatible endpoints and their own configured credentials.
An invoice always records its originating rail, rather than polling whichever
processor is currently first in the configuration.

BTCPay supports confirmation depths of 1, 2 or 6 through its invoice policy.
Requests for 3 through 5 round up to 6; a larger configured depth is refused.
Checkout rails also receive the exact confirmation count. Invoice creation pins
underpayment tolerance to zero, so a store's default cannot reduce the payment
required for access. Processor credentials remain server-side.

## Configuration and deployment

`PREMIUM_ENABLED` defaults to `false`. Enabling it requires a configured primary
payment processor, relay, `premium-post` admission policy, and valid plans.
`PREMIUM_PLANS` defines `id:days:amount` entries in `PREMIUM_CURRENCY`.
The [example configuration](../../.env.example) owns the variable names and defaults.
The [paid relay recipe](../../examples/paid-relay/README.md) illustrates independent
self-hosting; company production changes use reviewed Fleet plan/apply procedures.

The admission service binds to loopback by default. Setting `RELAY_MODE=external`
does not by itself authorize cross-host admission access. A relocation must
establish a protected admission path and preserve the same write policy.

## Verification

The relevant checks cover policy decisions, configuration refusal, real invoice
request serialization, single-use activation, renewal, cross-user binding and
expired-window capacity. Database tests require a disposable PostgreSQL database;
a run that skips them does not establish payment correctness. OpenAPI is generated
from the handlers and must be regenerated when the public contract changes.

## Release checklist

- [ ] Keep premium and additional rails disabled until explicitly configured.
- [ ] Verify the configured processor can create and read its own invoices.
- [ ] Run database regressions and payment transport tests for the exact candidate.
- [ ] Confirm paid activation, expiry and renewal with the selected processor.
- [ ] Verify free wallet events and premium general posting at relay admission.
- [ ] Describe prepaid access and the actual instance's price in client copy.
