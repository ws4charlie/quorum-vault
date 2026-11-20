#!/usr/bin/env bash
# The smoke set (design note K8s-deployment.md §9). Each case is a script here; this runs them in order and says which failed.
#   ci/kind/smoke/run.sh [case ...]       cases: install netpol upgrade     (default: all that exist)
# Placeholders, not half-tests: rotation (item 4), admission (item 6), tee-sim (item 8) and the signing cases (2, 3) are listed by `run.sh --pending`.
set -uo pipefail
here="$(dirname "${BASH_SOURCE[0]}")"
if [ "${1:-}" = "--pending" ]; then
  cat <<P
pending (not implemented, on purpose):
  withdrawal  EVM and Bitcoin through the real pods with MPC signing   needs qv-signing-core + qv-party x3 installed and a DKG (README "Status")
  crash       delete party A mid-sign, a worker, roll the gateway       needs withdrawal
  rotation    certificate rotation without restart; expired cert refuses start   (design item 4, later)
  admission   unsigned image refused; ConfigMap edit refused           (design item 6, the policy hand's task)
  teesim      tee-sim profile                                          (design item 8, later)
P
  exit 0
fi
cases=("$@"); [ ${#cases[@]} -gt 0 ] || cases=(install netpol upgrade)
fail=()
for c in "${cases[@]}"; do
  echo "=== $c"
  if "$here/$c.sh"; then echo "--- $c: ok"; else echo "--- $c: FAILED"; fail+=("$c"); fi
done
[ ${#fail[@]} -eq 0 ] && { echo "smoke: all ok"; exit 0; }
echo "smoke: FAILED: ${fail[*]}"; exit 1
