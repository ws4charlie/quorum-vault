#!/usr/bin/env bash
# Onboards one AgentGate into this checkout's kind cluster (after `make kind-up`) and writes everything Gate needs into an output directory, one file per value
# (README, "AgentGate onboarding"). Idempotent: run it again and it changes nothing (no second client, wallet or token; funding tops up to --fund).
#   ci/kind/gate.sh --pubkey FILE --kid KID [--namespace agentgate] --fund ATOMIC_USDC --out DIR
#   make kind-gate PUBKEY=FILE KID=KID NAMESPACE=agentgate FUND=ATOMIC_USDC OUT=DIR
# Relative paths are read against the caller's directory, so another repository can call "$QV_REPO/ci/kind/gate.sh" from its own. QV_KIND_NAME names the cluster.
#
# What it does, all kind-only and from the lane's gitignored work dir (nothing secret is printed or written outside it and OUT):
#   - the mock USDC with EIP-3009 on anvil (deployed once, its address kept in the work dir) and the Gate wallet (the lane's EVM hot shard 0) holding --fund of it
#   - the zone: USDC with x402 on hot shard 0 and two operators (keys made once in the work dir) in the gateway's and the cosigners' config; the gate setting
#     (Gate's key, the wallet, small fast-lane limits) signed by both operators and applied to the three guard databases with qv-approvers
#   - Keycloak: realm role `gate` and the confidential client `agentgate` (client credentials only) with that role; its secret goes to OUT/client_secret only
#   - the core: the gate section and USDC in the custody config, `agentgate.enabled` and the client in oidc.serviceClients (helm --set: values-kind.yaml stays
#     as it is), and the books' USDC on the wallet topped up to --fund
#   - the certificate: Gate's client certificate (qv-certs catalog entry `agentgate`, Secret qv-agentgate-tls) copied to OUT
#   - the network: NetworkPolicies that let --namespace reach the core's port, Keycloak's port and anvil's port, nothing else; a Service `qv-core` (the name in
#     the core's server certificate) so Gate dials a name that the certificate carries
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
usage() { echo "usage: gate.sh --pubkey FILE --kid KID [--namespace agentgate] --fund ATOMIC_USDC --out DIR" >&2; exit 2; }
abs() { case "$1" in /*) printf %s "$1";; *) printf %s "$PWD/$1";; esac; }
PUBKEY="" KID="" GNS=agentgate FUND="" OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --pubkey) PUBKEY="$(abs "${2:?}")"; shift 2;;
    --kid) KID="${2:?}"; shift 2;;
    --namespace) GNS="${2:?}"; shift 2;;
    --fund) FUND="${2:?}"; shift 2;;
    --out) OUT="$(abs "${2:?}")"; shift 2;;
    *) usage;;
  esac
done
[ -n "$PUBKEY" ] && [ -n "$KID" ] && [ -n "$FUND" ] && [ -n "$OUT" ] || usage
[ -s "$PUBKEY" ] || { echo "gate.sh: no public key file $PUBKEY" >&2; exit 2; }
[[ "$FUND" =~ ^[0-9]+$ ]] || { echo "gate.sh: --fund must be atomic USDC units (an integer)" >&2; exit 2; }
[[ "$KID" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "gate.sh: --kid must be 1-64 of [A-Za-z0-9._-]" >&2; exit 2; }
[[ "$GNS" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || { echo "gate.sh: --namespace is not a namespace name" >&2; exit 2; }
. "$here/lib.sh"
trace_failures
cd "$QV_KIND_ROOT"
S="$WORK/secrets"; C="$WORK/cfg"; G="$WORK/gate"; mkdir -p "$G" "$OUT"; chmod 700 "$G" "$OUT"
[ -s "$C/signing.json" ] && [ -s "$C/custody-evm.json" ] || { echo "gate.sh: no lane configs in $C: run make kind-up first (cluster $QV_KIND_NAME)" >&2; exit 1; }
AUDIENCE=qv-kind CLIENT=agentgate
PF_PIDS=() PF_LOGS=()
fwd() { pf_start "$2" "$3" "$4"; PF_PIDS+=("$PF_PID"); PF_LOGS+=("$PF_LOG"); printf -v "$1" %s "$PF_PORT"; }
fwd_stop() { local p; for p in "${PF_PIDS[@]:-}"; do [ -z "$p" ] || kill "$p" 2>/dev/null || true; done; for p in "${PF_LOGS[@]:-}"; do [ -z "$p" ] || rm -f "$p"; done; PF_PIDS=() PF_LOGS=(); }
cleanup() { fwd_stop; rm -rf "$G/tmp"; }
trap cleanup EXIT
mkdir -p "$G/tmp"; chmod 700 "$G/tmp"
log "build the lane's gate helper"
go build -o "$G/kindgate" ./ci/kind/tools/kindgate

# ---- 1. the wallet and the token
[ -s "$G/wallet_id" ] || { h="$(openssl rand -hex 16)"; printf '%s-%s-4%s-%x%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" "$(( (0x${h:16:1} & 3) | 8 ))" "${h:17:3}" "${h:20:12}" > "$G/wallet_id"; }
WALLET_ID="$(cat "$G/wallet_id")"
WALLET="$(jq -r '.chain.hot_shards[0]' "$C/custody-evm.json")"
log "mock USDC on anvil ($QV_KIND_CHAIN_ID), wallet $WALLET topped up to $FUND"
fwd P_ANVIL "$NS_BIZ" svc/anvil 8545
USDC="$("$G/kindgate" usdc -rpc "http://127.0.0.1:$P_ANVIL" -chain-id "$QV_KIND_CHAIN_ID" -state "$G/usdc_address" -to "$WALLET" -fund "$FUND" -pending "$G/usdc-mints")"

# ---- 2. the configs: the zone's and the core's, and the gate setting (validated by the services' own parsers)
"$G/kindgate" cfg -in "$C" -out "$G" -usdc "$USDC" -wallet-id "$WALLET_ID" -audience "$AUDIENCE" -kid "$KID" -pubkey "$PUBKEY" -ops "$S" > "$G/tmp/cfg.json"
PART="$(jq -r .partition "$G/tmp/cfg.json")"

# ---- 3. the zone: the gateway and both cosigners get the configs with the token, x402 and the operators (no change: helm replaces no pod)
log "signing zone: gateway and cosigners with USDC x402 and the operators section"
jq '{cosigner:{config:.}}' "$G/cosigner.json" > "$G/tmp/cosigner-config.yaml"
pids=()
hm upgrade --install qv-signing-core deploy/helm/qv-signing-core -n "$NS_SIGN" -f deploy/helm/qv-signing-core/values-kind.yaml $(trust_args "$NS_SIGN") --set hsm.mode=none \
  --set-file config.signing="$G/signing.json" --wait --timeout 6m > /dev/null & pids+=("$!")
for r in b c; do
  ns="$NS_B"; [ "$r" = c ] && ns="$NS_C"
  hm upgrade --install "qv-party-$r" deploy/helm/qv-party -n "$ns" --set role="$(echo $r | tr a-z A-Z)" -f deploy/helm/qv-party/values-kind.yaml $(trust_args "$ns") \
    -f "$WORK/party-$r.yaml" -f "$G/tmp/cosigner-config.yaml" --wait --timeout 6m > /dev/null & pids+=("$!")
done
wait_all "${pids[@]}"

# ---- 4. the gate setting: signed by both operators, applied to every guard database (skipped when the same setting is in force everywhere)
log "gate setting: sign (op1, op2) and apply to gateway, cosigner-b, cosigner-c"
go build -o "$G/qv-approvers" ./cmd/qv-approvers
# the three guard databases, each through its own port-forward with the certificate of the service that owns it (gateway: role and database
# qv_gateway_guard; cosigner B/C: role qv_cosigner_<b|c>_guard, database qv_cosigner_guard), as the chart's signed-settings Job logs in. A forward dies when
# Postgres resets a connection (kubectl "lost connection to pod"), so each qv-approvers call gets fresh ones.
guards_up() {
  local row name ns db role d port
  guards=()
  for row in "gateway $NS_SIGN qv_gateway_guard qv_gateway_guard" "cosigner-b $NS_B qv_cosigner_guard qv_cosigner_b_guard" "cosigner-c $NS_C qv_cosigner_guard qv_cosigner_c_guard"; do
    read -r name ns db role <<< "$row"; d="$G/tmp/$name"
    if [ ! -s "$d/tls.key" ]; then
      mkdir -p "$d"
      for f in tls.crt tls.key ca.crt; do kn "$ns" get secret "qv-signing-$name-tls" -o jsonpath="{.data.${f//./\\.}}" | base64 -d > "$d/$f"; done; chmod 600 "$d/tls.key"
    fi
    fwd port "$ns" svc/qv-guard-rw 5432
    guards+=(-guard-dsn "$name=postgres://$role@127.0.0.1:$port/$db?sslmode=verify-full&sslrootcert=$d/ca.crt&sslcert=$d/tls.crt&sslkey=$d/tls.key")
  done
}
approvers() { # CMD [FILE...]: qv-approvers with the Gate zone config and the three guard databases; the forwards it opened are closed after
  local cmd="$1" n="${#PF_PIDS[@]}" rc=0 i; shift
  guards_up
  "$G/qv-approvers" "$cmd" -config "$G/signing.json" "${guards[@]}" "$@" || rc=$?
  for ((i = n; i < ${#PF_PIDS[@]}; i++)); do kill "${PF_PIDS[$i]}" 2>/dev/null || true; rm -f "${PF_LOGS[$i]}"; done
  PF_PIDS=("${PF_PIDS[@]:0:$n}") PF_LOGS=("${PF_LOGS[@]:0:$n}")
  return $rc
}
show="$(approvers gate-show)"
next="$(sed -n 's/.*(next version \([0-9]*\)).*/\1/p' <<< "$show" | sort -n | tail -1)"
want="$(jq -cS . "$G/setting.json")"
if [ -s "$G/applied.json" ] && [ "$(jq -cS .setting "$G/applied.json")" = "$want" ] && \
   [ "$(sed -n 's/.*(next version \([0-9]*\)).*/\1/p' <<< "$show" | sort -u)" = "$(( $(jq .version "$G/applied.json") + 1 ))" ]; then
  echo "gate setting version $(jq .version "$G/applied.json") is in force everywhere: nothing to apply" >&2
else
  v="$next"
  "$G/qv-approvers" gate-sign -operator op1 -key "$S/op1.key" -setting "$G/setting.json" -version "$v" -out "$G/tmp/gate-v.json" 2>/dev/null
  "$G/qv-approvers" gate-sign -operator op2 -key "$S/op2.key" -join "$G/tmp/gate-v.json" -out "$G/tmp/gate-v.json" 2>/dev/null
  approvers gate-apply "$G/tmp/gate-v.json" >&2
  jq -n --argjson v "$v" --argjson s "$want" '{version:$v, setting:$s}' > "$G/applied.json"
fi

# ---- 5. Keycloak: realm role `gate`, client `agentgate` (client credentials only) with only that role
log "Keycloak: client $CLIENT with role gate"
fwd P_KC "$NS_BIZ" svc/keycloak 8443
KC="https://keycloak.$NS_BIZ.svc:$P_KC"
kc() { curl -sS --fail-with-body --cacert "$S/ca-business.crt" --resolve "keycloak.$NS_BIZ.svc:$P_KC:127.0.0.1" -H "Authorization: Bearer $ADM" "$@"; }
tr -d '\n' < "$S/kc-admin" > "$G/tmp/kc-admin"   # the bootstrap admin's password, without the newline the work dir file ends in
ADM="$(curl -sS --fail-with-body --cacert "$S/ca-business.crt" --resolve "keycloak.$NS_BIZ.svc:$P_KC:127.0.0.1" "$KC/realms/master/protocol/openid-connect/token" \
  --data-urlencode grant_type=password --data-urlencode client_id=admin-cli --data-urlencode username=admin --data-urlencode password@"$G/tmp/kc-admin" | jq -r .access_token)"
R="$KC/admin/realms/quorumvault"
kc -o /dev/null "$R/roles/gate" 2>/dev/null || kc -H 'Content-Type: application/json' -d '{"name":"gate","description":"AgentGate: POST /v2/gate/signatures only"}' "$R/roles"
CID="$(kc "$R/clients?clientId=$CLIENT" | jq -r '.[0].id // empty')"
if [ -z "$CID" ]; then
  jq -n --arg c "$CLIENT" '{clientId:$c, name:"Service identity: AgentGate (client credentials)", enabled:true, protocol:"openid-connect", publicClient:false,
    clientAuthenticatorType:"client-secret", serviceAccountsEnabled:true, standardFlowEnabled:false, directAccessGrantsEnabled:false, implicitFlowEnabled:false,
    defaultClientScopes:["basic","qv-roles","qv-core-audience"], optionalClientScopes:[]}' | kc -H 'Content-Type: application/json' -d @- "$R/clients"
  CID="$(kc "$R/clients?clientId=$CLIENT" | jq -r '.[0].id')"
fi
SA="$(kc "$R/clients/$CID/service-account-user" | jq -r .id)"
if ! kc "$R/users/$SA/role-mappings/realm" | jq -e 'any(.[]; .name=="gate")' > /dev/null; then
  kc "$R/roles/gate" | jq -c '[{id,name}]' | kc -H 'Content-Type: application/json' -d @- "$R/users/$SA/role-mappings/realm"
fi
# only `gate`: the realm's default roles (offline_access, uma_authorization) are taken off the service account, so the token carries the one role
kc "$R/users/$SA/role-mappings/realm" | jq -c '[.[] | select(.name!="gate") | {id,name}]' > "$G/tmp/extra-roles.json"
[ "$(jq length "$G/tmp/extra-roles.json")" = 0 ] || kc -X DELETE -H 'Content-Type: application/json' -d @"$G/tmp/extra-roles.json" "$R/users/$SA/role-mappings/realm"
( umask 077; kc "$R/clients/$CID/client-secret" | jq -r .value > "$OUT/client_secret" )
[ -s "$OUT/client_secret" ] && [ "$(cat "$OUT/client_secret")" != null ] || { echo "gate.sh: Keycloak gave no client secret" >&2; exit 1; }

# ---- 6. the core: custody config with the gate section, agentgate on, the client a service client
log "core: gate section, agentgate.enabled, service client $CLIENT"
old="$(kn "$NS_BIZ" get secret qv-custody-config -o jsonpath='{.data.config\.json}' | base64 -d | shasum | cut -c1-40)"
kn "$NS_BIZ" create secret generic qv-custody-config --from-file=config.json="$G/custody.json" --dry-run=client -o yaml | k apply -f - > /dev/null
hm upgrade --install qv-business deploy/helm/qv-business -n "$NS_BIZ" -f deploy/helm/qv-business/values-kind.yaml $(trust_args "$NS_BIZ") \
  --set agentgate.enabled=true --set oidc.serviceClients="$CLIENT" --wait --timeout 6m > /dev/null
if [ "$old" != "$(shasum < "$G/custody.json" | cut -c1-40)" ]; then # the custody config is a Secret: a new one is read on restart only
  kn "$NS_BIZ" rollout restart deploy/qv-business-core deploy/qv-business-worker deploy/qv-business-relay > /dev/null
fi
for d in core worker relay; do kn "$NS_BIZ" rollout status deploy/qv-business-$d --timeout=180s > /dev/null; done

log "books: each USDC mint on hot:$PART (the books follow the chain mint by mint)"
fwd P_DB "$NS_BIZ" svc/qv-business-db-rw 5432
d="$G/tmp/core"; mkdir -p "$d"
for f in tls.crt tls.key ca.crt; do kn "$NS_BIZ" get secret qv-core-tls -o jsonpath="{.data.${f//./\\.}}" | base64 -d > "$d/$f"; done; chmod 600 "$d/tls.key"
"$G/kindgate" book -cfg "$G/custody.json" -rpc "http://127.0.0.1:$P_ANVIL" -pending "$G/usdc-mints" \
  -dsn "postgres://qv_core@127.0.0.1:$P_DB/quorumvault?sslmode=verify-ca&sslrootcert=$d/ca.crt&sslcert=$d/tls.crt&sslkey=$d/tls.key" >&2

# ---- 7. the network: the Gate namespace reaches three ports, nothing else; the core under the name its certificate carries
log "network: $GNS may reach core:8443, keycloak:8443, anvil:8545"
k create namespace "$GNS" --dry-run=client -o yaml | k apply -f - > /dev/null
core_sel='{"app.kubernetes.io/name":"qv","app.kubernetes.io/instance":"qv-business","app.kubernetes.io/component":"core"}'
np() { # name selector port
  jq -n --arg n "qv-gate-$GNS-$1" --arg ns "$NS_BIZ" --arg g "$GNS" --argjson sel "$2" --argjson p "$3" \
    '{apiVersion:"networking.k8s.io/v1",kind:"NetworkPolicy",metadata:{name:$n,namespace:$ns,labels:{"quorumvault.io/gate-onboarding":$g}},
      spec:{podSelector:{matchLabels:$sel},policyTypes:["Ingress"],ingress:[{from:[{namespaceSelector:{matchLabels:{"kubernetes.io/metadata.name":$g}}}],ports:[{port:$p,protocol:"TCP"}]}]}}'
}
{ np core "$core_sel" 8443; np keycloak '{"app":"keycloak"}' 8443; np anvil '{"app":"chain-stub","chain":"anvil"}' 8545
  jq -n --arg ns "$NS_BIZ" --argjson sel "$core_sel" '{apiVersion:"v1",kind:"Service",metadata:{name:"qv-core",namespace:$ns},
    spec:{type:"ClusterIP",selector:$sel,ports:[{name:"https",port:8443,targetPort:"https",protocol:"TCP"}]}}'
} | jq -s '{apiVersion:"v1",kind:"List",items:.}' | k apply -f - > /dev/null

# ---- 8. the output directory (PHASE2 contract: one file per value)
log "output: $OUT"
for f in tls.crt tls.key; do kn "$NS_BIZ" get secret qv-agentgate-tls -o jsonpath="{.data.${f//./\\.}}" | base64 -d > "$OUT/$f"; done
chmod 600 "$OUT/tls.key"
cp "$S/ca-business.crt" "$OUT/ca.crt"; cp "$S/ca-business.crt" "$OUT/token_ca.crt"
w() { printf '%s\n' "$2" > "$OUT/$1"; }
w vault_url "https://qv-core.$NS_BIZ.svc:8443"
w token_url "https://keycloak.$NS_BIZ.svc:8443/realms/quorumvault/protocol/openid-connect/token"
w client_id "$CLIENT"
w audience "$AUDIENCE"
w wallet_id "$WALLET_ID"
w wallet_address "$WALLET"
w chain_id "$QV_KIND_CHAIN_ID"
w rpc_url "http://anvil.$NS_BIZ.svc:8545"
w usdc_address "$USDC"
log "done: Gate $KID onboarded, wallet $WALLET_ID ($WALLET), USDC $USDC"
