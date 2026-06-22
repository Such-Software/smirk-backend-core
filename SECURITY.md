# Security Policy

## Reporting a vulnerability

Please report security issues **privately**. Do not open public issues or pull
requests for vulnerabilities.

- Email: security@smirk.cash
- Encrypt sensitive reports with our PGP key (fingerprint published at
  `https://smirk.cash/.well-known/security.txt`).

Include enough detail to reproduce: affected endpoint/component, version or
commit, and a proof of concept where possible. We aim to acknowledge reports
within 72 hours and to keep you updated as we triage and fix.

## Scope

This repository (`smirk-backend-core`) — the self-hostable backend. Issues in
node software it talks to (Bitcoin/Litecoin/Monero/Wownero/Grin daemons,
light-wallet servers, Electrum) should be reported to those projects, though
we welcome reports about how this backend uses them.

## Operating securely

`smirk-backend-core` is non-custodial: it never stores seeds or spend keys.
The admin surface authenticates with seed-derived public keys ("Sign in with
Smirk") and stores only public keys. Default deployment posture binds admin and
setup to loopback / a Tor hidden service. See `docs/` for the hardening guide.
