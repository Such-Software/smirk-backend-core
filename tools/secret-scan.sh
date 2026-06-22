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

# Secret shapes (not names): PEM/OpenSSH/PGP private-key blocks and seed phrases.
PATTERNS='(-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY|\b(mnemonic|seed[_ ]?phrase)\b\s*[:=])'

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
