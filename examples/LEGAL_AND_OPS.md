# Legal & operational considerations (per recipe)

> **This is not legal advice.** It's a plain-English checklist of what changes,
> legally and operationally, as you pick a heavier recipe — so you know what to take
> to your own lawyer. Smirk's own published [Terms](https://smirk.cash/terms) +
> [Privacy Policy](https://smirk.cash/privacy) (source in the `smirk-website` repo)
> are a useful worked example for a non-custodial, multi-chain, Nostr-enabled wallet
> backend — but they are **ours**. Adapt with your own counsel; don't copy blind.

## The through-line: stay non-custodial

Every recipe keeps the backend **non-custodial** — you never hold seeds, spend keys,
or user funds. That single property is what keeps you out of money-transmitter /
custodial-exchange territory. Preserve it in anything you add.

## By recipe

**`personal` / `friends`** — lowest surface; you're running infrastructure for
yourself or a known group. If you enable the relay, you're carrying (encrypted)
messages — see *Running a relay*.

**`public-free`** — open to the public, so have a Terms + Privacy that disclose what
your backend actually receives: Monero/Wownero **view keys** (for LWS scanning),
**IP handling** (hash + purpose), the wallet **fingerprint**, and **Nostr identity**.
No money changes hands → no payment/consumer-sale angle.

**`paid-access` / `paid-relay` (you charge a fee)**
- You're selling access to **your** service (a fee), not transmitting user funds → you
  act as a **merchant**, not a money transmitter. Keep it non-custodial and
  **pull-model** (read invoice status; never hold or route user funds).
- Terms should state: what the fee buys, **no refunds** (prepaid access), the service
  is best-effort and may change, and **fair-use limits** (bandwidth / storage / content)
  for relay posting.
- Treat fees as **business income** (taxes). Confirm your jurisdiction + entity, and
  have counsel bless the non-custodial → not-an-MSB analysis for *you*.

**Running a relay (`friends` / `paid-relay` / `community`)** — you're hosting user
content, which is intermediary-liability territory:
- **Copyright (DMCA):** consider registering a **Designated Agent** with the U.S.
  Copyright Office and running a notice / counter-notice process with a named contact.
- **CSAM:** U.S. providers hosting content have mandatory reporting duties (NCMEC /
  18 U.S.C. §2258A) — register and have a process. Note that **end-to-end-encrypted**
  DMs you cannot read are handled differently from plaintext you can.
- **Acceptable use + moderation rights:** prohibit unlawful content; reserve the right
  to rate-limit, refuse, or remove; state that you are **not the author** of user
  content and don't guarantee delivery/retention.
- Smirk's Terms **§6** (reporting, DMCA, acceptable use) and **§9.1** (relay) are a
  worked example of this posture.

## Again: a reference, not a template

Use Smirk's live docs to see *how one operator did it* — then write your own with a
lawyer. Requirements vary by country, entity, and exactly what you enable.
