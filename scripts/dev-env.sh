#!/usr/bin/env bash
# Writes ./.env (gitignored) with freshly generated random SoftHSM PINs. Never overwrites an existing .env.
# Run it once on a fresh checkout (`make dev-env`), before `make softhsm`. CI runs it too.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"

if [ -e "$ENV_FILE" ]; then
  echo "dev-env: $ENV_FILE exists, left as it is"
  exit 0
fi

rand() { # rand: 24 random hex characters
  if command -v openssl >/dev/null; then openssl rand -hex 12; else head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

so_pin="$(rand)"
user_pin="$(rand)"
tmp="$(mktemp "$ROOT/.env.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
# Only the PINs: the other variables in .env.example stay unset, so a Makefile that loads .env does not override the environment (scripts/e2e-all.sh).
printf '# Written by scripts/dev-env.sh; random, local, gitignored. See .env.example for the other variables.\nQV_HSM_SO_PIN=%s\nQV_HSM_PIN=%s\n' "$so_pin" "$user_pin" >"$tmp"
chmod 600 "$tmp"
mv "$tmp" "$ENV_FILE"
trap - EXIT
echo "dev-env: wrote $ENV_FILE with new random SoftHSM PINs"
