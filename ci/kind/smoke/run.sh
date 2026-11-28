#!/usr/bin/env bash
# The smoke set (design note K8s-deployment.md §9). Each case is a script here; this runs them in order and says which failed.
#   ci/kind/smoke/run.sh [case ...]       cases: install netpol withdraw crash upgrade admission certs gate teesim  (default: all that exist; gate after the cases that withdraw
#                                         ETH and after upgrade, see smoke/gate.sh; teesim last, it replaces the three parties)
# Each case's whole output also goes to its own log file (QV_KIND_SMOKE_LOGS, default the lane's work dir), and the full output of every failed case is printed
# again at the end, so a CI log that shows only the tail still has the cause.
set -uo pipefail
here="$(dirname "${BASH_SOURCE[0]}")"
if [ "${1:-}" = "--pending" ]; then
  cat <<P
pending (not implemented, on purpose):
  none
P
  exit 0
fi
logs="${QV_KIND_SMOKE_LOGS:-}"
if [ -z "$logs" ]; then logs="$(. "$here/../lib.sh" && echo "$WORK/smoke-logs")"; fi
mkdir -p "$logs"
cases=("$@"); [ ${#cases[@]} -gt 0 ] || cases=(install netpol withdraw crash upgrade admission certs gate teesim)
fail=()
for c in "${cases[@]}"; do
  echo "=== $c"
  t=$SECONDS
  if "$here/$c.sh" 2>&1 | tee "$logs/$c.log"; then echo "--- $c: ok ($((SECONDS - t)) s)"; else echo "--- $c: FAILED ($((SECONDS - t)) s)"; fail+=("$c"); fi
done
[ ${#fail[@]} -eq 0 ] && { echo "smoke: all ok"; exit 0; }
for c in "${fail[@]}"; do
  echo "=== full output of the failed case $c ($logs/$c.log)"
  cat "$logs/$c.log"
  echo "=== end of $c"
done
echo "smoke: FAILED: ${fail[*]}"; exit 1
