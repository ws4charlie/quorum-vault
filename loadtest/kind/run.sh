#!/usr/bin/env bash
# The load generator against the kind lane (ci/kind/README.md): the same binary and scenarios as `make load-local`, aimed at the pods through port-forwards.
#   make kind-up                                   # the cluster, once
#   loadtest/kind/run.sh loadtest/scenarios/evm-kind.json [out-dir]
# Only auto-approved withdrawals and deposits: the kind lane has no approver keys for people (the worker's automated key approves the small tier).
# Needs the lane's custody config for the EVM chain (kindcfg writes it) and funded hot gas money (fund_hot, the lane's own step). Nothing is written into the repository:
# the target file, the funder key and the results go to the lane's gitignored work directory and to the out directory.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/../../ci/kind/smoke/wd-lib.sh" # lib.sh (cluster names, WORK) and the port-forward helpers; cd's to the repository root
scen="${1:?usage: run.sh SCENARIO [OUT]}"; out="${2:-$QV_KIND_ROOT/data/load/kind-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$out" "$WORK/load"
trap wd_down EXIT
use_custody evm # the pods serve the EVM chain (a Secret and a restart if they served Bitcoin); opens the forwards
fund_hot        # gas money in the hot shard's books: idempotent
key="$(openssl rand -hex 32)"; ( umask 077; printf %s "$key" > "$WORK/load/funder.key" )
addr="$(go run ./loadtest/cmd/qv-load addr -key-file "$WORK/load/funder.key")"
curl -fsS -X POST -H 'content-type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"anvil_setBalance\",\"params\":[\"$addr\",\"0x$(printf '%x' 1000000)000000000000000000\"]}" "http://127.0.0.1:$P_ANVIL" > /dev/null
cat > "$WORK/load/target.json" <<JSON
{"api": ["https://qv-core.qv.svc:8443"], "dial_addr": "127.0.0.1:$P_CORE", "ca_file": "$S/ca-business.crt", "tls_server_name": "qv-core.qv.svc",
 "token": {"kind": "keycloak", "url": "https://keycloak:8443", "dial_addr": "127.0.0.1:$P_KC", "ca_file": "$S/ca-business.crt", "tls_server_name": "keycloak", "secrets_dir": "$S"},
 "actors": {"initiator": "alice", "ops": "ops", "approvers": []},
 "evm": {"chain": "evm-kind", "rpc": "http://127.0.0.1:$P_ANVIL", "funder_key_file": "$WORK/load/funder.key", "chain_id": $QV_KIND_CHAIN_ID}}
JSON
go run ./loadtest/cmd/qv-load run -scenario "$scen" -target "$WORK/load/target.json" -out "$out" \
  -meta "shape=kind: the real charts on one node, three parties and DKG by pods; the generator and the chain are outside the cluster" \
  -meta "machine=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m), $(sysctl -n hw.ncpu 2>/dev/null || nproc) logical CPUs" \
  -meta "label=${QV_LOAD_LABEL:-kind}" -meta "git=$(git rev-parse --short HEAD)"
