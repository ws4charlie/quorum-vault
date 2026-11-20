#!/usr/bin/env bash
# The smoke set (design note K8s-deployment.md §9). Each case is a script here; this runs them in order and says which failed.
#   ci/kind/smoke/run.sh [case ...]       cases: install netpol upgrade withdraw crash admission certs     (default: all that exist)
# Placeholder, not a half-test: tee-sim (item 8) is listed by `run.sh --pending`.
set -uo pipefail
here="$(dirname "${BASH_SOURCE[0]}")"
if [ "${1:-}" = "--pending" ]; then
  cat <<P
pending (not implemented, on purpose):
  teesim      tee-sim profile                                          (design item 8, later)
P
  exit 0
fi
cases=("$@"); [ ${#cases[@]} -gt 0 ] || cases=(install netpol withdraw crash upgrade admission certs)
fail=()
for c in "${cases[@]}"; do
  echo "=== $c"
  if "$here/$c.sh"; then echo "--- $c: ok"; else echo "--- $c: FAILED"; fail+=("$c"); fi
done
[ ${#fail[@]} -eq 0 ] && { echo "smoke: all ok"; exit 0; }
echo "smoke: FAILED: ${fail[*]}"; exit 1
