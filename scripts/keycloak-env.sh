#!/usr/bin/env bash
# Adds random passwords for the dev Keycloak to ./.env (gitignored), for the ones that are not there yet: the admin console, the four test users and the
# guardian's client secret. The repo holds no credentials, not even test ones: deploy/keycloak/quorumvault-realm.json has ${PLACEHOLDERS} that Keycloak
# fills from these variables when it imports the realm, and the e2e harness reads the same variables. Run by `make keycloak-up`, scripts/e2e-all.sh and ci/infra.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"
[ -e "$ENV_FILE" ] || "$ROOT/scripts/dev-env.sh" >/dev/null
rand() { if command -v openssl >/dev/null; then openssl rand -hex 16; else head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi; }
added=""
for v in QV_KEYCLOAK_ADMIN_PASSWORD QV_TEST_PASSWORD_ALICE QV_TEST_PASSWORD_BOB QV_TEST_PASSWORD_CAROL QV_TEST_PASSWORD_OPS QV_KEYCLOAK_GUARDIAN_SECRET; do
  if ! grep -q "^$v=" "$ENV_FILE"; then
    printf '%s=%s\n' "$v" "$(rand)" >>"$ENV_FILE"
    added="$added $v"
  fi
done
chmod 600 "$ENV_FILE"
[ -z "$added" ] || echo "keycloak-env: wrote random values to $ENV_FILE:$added"
