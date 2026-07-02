# personal — your own sovereign backend

Run the backend for yourself alone: no registration gates, unlimited restore, the
relay optional. The smallest footprint; you are the only user.

- **Config:** [`.env.example`](.env.example) — all gates off,
  `WALLET_RESTORE_POLICY=unlimited`, relay off.
- **Boot:** copy `.env.example` → `.env`, generate the secrets (`openssl rand -hex 32`),
  fill your chain endpoints, run the binary (migrations apply on boot). Bind the API
  to `127.0.0.1` behind your own TLS.
- Non-custodial: the backend never sees your seed or spend keys — funds stay on-chain.
