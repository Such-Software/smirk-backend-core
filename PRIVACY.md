# Privacy Policy

The canonical Smirk privacy policy lives at **https://smirk.cash/privacy** and
describes the data practices of the instance operated by Such Software LLC
(api.smirk.cash).

## For operators who self-host

This backend is open source and self-hostable. **If you run your own instance, you
are an independent data controller for it** and the Such Software policy does not
speak for you. What your instance receives from wallets that connect to it:

- **Monero/Wownero view keys** (to scan for users' incoming funds; a view key
  cannot spend) and their scan/registration state.
- **Public addresses** for BTC/LTC balance lookups and **signed transactions** to
  broadcast. Recipient address and amount are not sent on broadcast.
- A one-way **seed fingerprint** (SHA-256) as a non-reversible wallet identifier.
- If enabled: the **username to npub** mapping published in your NIP-05 directory,
  and, for the relay, encrypted message envelopes (ciphertext only).
- IP addresses only as a **salted one-way hash**, for rate-limiting.

Private keys and seed phrases are never transmitted to the backend.

If you offer your instance to others, publish your own privacy policy describing
how you handle this data, your retention, and your jurisdiction. The knobs that
affect retention and data exposure (login-event and audit retention, erasure,
relay retention, landing-page exposure) are documented in
[docs/operations/CONSOLE.md](docs/operations/CONSOLE.md) and the root `.env.example`.
