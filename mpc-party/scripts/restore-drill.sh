#!/usr/bin/env bash
# One command: in a local stack (two mpc-party processes, shares sealed in SoftHSM tokens), destroy party B, restore it from
# its backup with the offline recovery key, and sign. Prints PASS or FAIL. Needs: the cb-mpc build, SoftHSM (scripts/setup-softhsm.sh
# at the repository root, run it once), Go.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .deps/BUILD_STAMP ] || scripts/fetch-build-cbmpc.sh
if [ -z "${SOFTHSM2_CONF:-}" ] && [ ! -f ../data/softhsm/softhsm2.conf ]; then
  echo "SoftHSM is not set up: run ../scripts/setup-softhsm.sh first" >&2; exit 1
fi
export QV_REQUIRE_HSM=1
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
if go test -count=1 -timeout 5m -run '^TestRestoreDrill$' -v ./e2e >"$out" 2>&1; then
  grep -E 'DRILL ' "$out" | sed -E 's/^[[:space:]]*[a-z_]+\.go:[0-9]+: //'
  echo "PASS"
else
  cat "$out"; echo "FAIL" >&2; exit 1
fi
