#!/usr/bin/env bash
# Case: the pods that sign or drive a withdrawal die in the middle of it, and the withdrawal still settles ONCE (one payout of exactly the amount, Reconcile clean):
#   1. party A is deleted while the sign job is in flight (the gateway falls back to coordinator B, party A comes back from its StatefulSet and its volume)
#   2. the worker is deleted right after the sign job exists (Temporal replays the workflow on the new worker)
#   3. the gateway is rolled while the withdrawal is signing (a new gateway pod finds the job in the queue and the guard database)
# Stands alone after a fresh `kind-up`: it books the hot shard's gas money itself (fund_hot, idempotent) and makes its own customer.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/wd-lib.sh"
trap wd_down EXIT
use_custody evm
fund_hot
AMT=10000000000000000
wd setup -asset ETH -customer kind-crash -amount 5000000000000000000 -hot "$(evm_hot)"

crash() { # name command-that-kills
  local name="$1"; shift
  echo "-- $name"
  local out; out="$(wd pay -asset ETH -customer kind-crash -amount $AMT)"; echo "$out"
  local id to; id="$(jq -r .id <<< "$out")"; to="$(jq -r .to <<< "$out")"
  wd await -id "$id" -until signing,broadcast,confirmed
  "$@" > /dev/null
  wd settle -asset ETH -id "$id" -to "$to" -amount $AMT
}
ready() { local ns="$1"; shift; kn "$ns" wait --for=condition=Ready pod "$@" --timeout=180s > /dev/null; }
crash "party A deleted mid-sign" kn "$NS_SIGN" delete pod qv-party-a-0 --wait=false
ready "$NS_SIGN" -l app.kubernetes.io/name=qv-party
crash "worker deleted after the sign job" kn "$NS_BIZ" delete pod -l app.kubernetes.io/component=worker --wait=false
kn "$NS_BIZ" rollout status deploy/qv-business-worker --timeout=180s > /dev/null
crash "gateway rolled while signing" kn "$NS_SIGN" rollout restart deploy/qv-signing-core-gateway
kn "$NS_SIGN" rollout status deploy/qv-signing-core-gateway --timeout=180s > /dev/null
# the kills above hit a signature that takes about a tenth of a second, so they may land before or after it. This one is certain: party A is gone for the whole withdrawal, and the gateway
# must sign through coordinator B (the cosigner of B authorises, party C is the second share)
echo "-- party A down for the whole withdrawal"
kn "$NS_SIGN" scale statefulset/qv-party-a --replicas=0 > /dev/null
kn "$NS_SIGN" wait --for=delete pod/qv-party-a-0 --timeout=120s > /dev/null
out="$(wd pay -asset ETH -customer kind-crash -amount $AMT)"; echo "$out"
wd settle -asset ETH -id "$(jq -r .id <<< "$out")" -to "$(jq -r .to <<< "$out")" -amount $AMT
kn "$NS_SIGN" scale statefulset/qv-party-a --replicas=1 > /dev/null
ready "$NS_SIGN" -l app.kubernetes.io/name=qv-party
# every withdrawal above was paid exactly once (settle checks the balance of each fresh destination); nothing was left open
wd reconcile
echo "crash: ok"
