#!/usr/bin/env bash
#
# secret-scan: block private keys and seed material from entering the tree.
#
# Public-safe by design: it matches on secret *shapes* (key blocks, mnemonic
# markers), never on project-internal names. gitleaks runs alongside it in CI
# for broad token/credential patterns.
#
#   ./tools/secret-scan.sh
#
set -uo pipefail
cd "$(dirname "$0")/.."

if git rev-parse --is-inside-work-tree >/dev/null 2>&1 && [ -n "$(git ls-files)" ]; then
  mapfile -t FILES < <(git ls-files)
else
  mapfile -t FILES < <(find . -type f -not -path './.git/*' -not -path './target/*' -printf '%P\n')
fi

# Secret shapes (not names), covering the classes this backend actually handles:
#   - PEM/OpenSSH/PGP private-key blocks
#   - seed-phrase markers (mnemonic / seed phrase), any capitalisation
#   - nsec1... Nostr SECRET keys (bech32)
#   - a secret-shaped env assignment given a 32+ hex-char value, i.e. an
#     `openssl rand -hex 32` value pasted in cleartext. The name alternation is
#     spelled out so it really does cover every secret this backend takes:
#     *_PEPPER, *_SALT, *_SECRET (incl. *_INTEGRITY_SECRET), *_PASSWORD, *_TOKEN,
#     *_API_KEY, *_ADMIN_KEY, *_HMAC_KEY, *_PRIVATE_KEY, *_SIGNING_KEY. A bare
#     *KEY* is NOT in the list on purpose: it would fire on ADMIN_PUBKEYS and
#     friends, whose values are public.
#
# NOT covered, and left to gitleaks rather than implied here: secret VALUES that
# are not hex (base64 or random alphanumeric API keys, real passwords). Catching
# those needs entropy heuristics, which in this tree would fire on every address,
# hash and test vector and train people to ignore the scanner.
PATTERNS='(-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY|\b([Mm]nemonic|MNEMONIC|[Ss]eed[_ ]?[Pp]hrase|SEED[_ ]?PHRASE)\b\s*[:=]|nsec1[0-9a-z]{20,}|\b[A-Z_]*(PEPPER|SALT|SECRET|PASSWORD|TOKEN|API_?KEY|ADMIN_KEY|HMAC_KEY|PRIVATE_KEY|SIGNING_KEY)[A-Z_]*\s*=\s*[0-9a-fA-F]{32,})'

fail=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  case "$f" in tools/secret-scan.sh) continue ;; esac
  if grep -EnI "$PATTERNS" "$f" >/dev/null 2>&1; then
    echo "SECRET-SCAN: possible key/seed material in $f"
    grep -EnI "$PATTERNS" "$f" | sed 's/^/    /'
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "SECRET-SCAN FAILED — remove key/seed material before committing."
  exit 1
fi
echo "secret-scan OK (${#FILES[@]} files checked)."
