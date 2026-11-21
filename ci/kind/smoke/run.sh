#!/usr/bin/env bash
# The smoke set (design note K8s-deployment.md §9). Each case is a script here; this runs them in order and says which failed.
#   ci/kind/smoke/run.sh [case ...]       cases: install netpol upgrade withdraw crash admission certs teesim  (default: all that exist; teesim last, it replaces the three parties)
set -uo pipefail
here="$(dirname "${BASH_SOURCE[0]}")"
if [ "${1:-}" = "--pending" ]; then
  cat <<P
pending (not implemented, on purpose):
  none
P
  exit 0
fi
cases=("$@"); [ ${#cases[@]} -gt 0 ] || cases=(install netpol withdraw crash upgrade admission certs teesim)
fail=()
for c in "${cases[@]}"; do
  echo "=== $c"
  if "$here/$c.sh"; then echo "--- $c: ok"; else echo "--- $c: FAILED"; fail+=("$c"); fi
done
[ ${#fail[@]} -eq 0 ] && { echo "smoke: all ok"; exit 0; }
echo "smoke: FAILED: ${fail[*]}"; exit 1
