#!/usr/bin/env bash
# Phase 3a: the guard databases' roles, the three parties (qv-party A, B, C) and the DKG. Run by charts.sh. Idempotent.
# Operator work done from the host here (qv-migrate -zone signing, CREATE DATABASE, the DKG through kindctl) is what an operator does with a Job or `kubectl exec` in production.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
trace_failures
cd "$QV_KIND_ROOT"
S="$WORK/secrets"
crt() { kn "$1" get secret "$2" -o jsonpath='{.data.tls\.crt}' | base64 -d; }
key() { kn "$1" get secret "$2" -o jsonpath='{.data.tls\.key}' | base64 -d; }
# the pin the parties check: SHA-256 of the certificate's public key (SubjectPublicKeyInfo)
pin() { crt "$1" "$2" | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex | awk '{print $NF}'; }
sel() { echo "{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $1 } } }"; }
rndpin() { [ -s "$S/$1" ] || ( umask 077; openssl rand -hex 8 | tr a-f 0-5 > "$S/$1" ); cat "$S/$1"; }

guard_setup() { # ns database role-name: roles from qv-migrate -zone signing (the repository's own tool), then the database the role owns, as signing_roles.sql says
  local ns="$1" db="$2" owner="$3" d
  d="$(mktemp -d)"; chmod 700 "$d"
  crt "$ns" qv-signing-admin-tls > "$d/c.crt"; key "$ns" qv-signing-admin-tls > "$d/c.key"; chmod 600 "$d/c.key"; kn "$ns" get secret qv-signing-admin-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > "$d/ca.crt"
  pf_start "$ns" svc/qv-guard-rw 5432
  go run ./cmd/qv-migrate -zone signing -enable-login -dsn "postgres://qv@127.0.0.1:$PF_PORT/qv_signing?sslmode=verify-full&sslrootcert=$d/ca.crt&sslcert=$d/c.crt&sslkey=$d/c.key"
  pf_stop; rm -rf "$d"
  # the primary pod must be Ready before an exec: the cluster's Ready condition and the pod can differ by a moment on a busy runner
  kn "$ns" wait pod/qv-guard-1 --for=condition=Ready --timeout=180s > /dev/null
  pg() { kn "$ns" exec qv-guard-1 -c postgres -- psql -U postgres -v ON_ERROR_STOP=1 -Atqc "$1"; }
  [ "$(pg "SELECT 1 FROM pg_database WHERE datname='$db'")" = 1 ] || pg "CREATE DATABASE $db OWNER $owner"
  pg "REVOKE CONNECT ON DATABASE $db FROM PUBLIC"
}

log "guard databases"
guard_setup "$NS_SIGN" qv_gateway_guard qv_gateway_guard
# each cosigner has its own certificate name and role (cosigner-b, cosigner-c); the database keeps the name qv_cosigner_guard (docs/runbooks/certificates.md, "Cosigner names")
guard_setup "$NS_B" qv_cosigner_guard qv_cosigner_b_guard
guard_setup "$NS_C" qv_cosigner_guard qv_cosigner_c_guard

log "parties"
ADMIN_KEYS="$(go run ./ci/kind/tools/kindctl adminkey -seed "$S/admin.seed" | sed 's/.*/"&"/' | paste -sd, -)"  # three admin keys, two must sign (adminThreshold)
for n in $NS_SIGN $NS_B $NS_C; do
  kn "$n" create secret generic qv-party-hsm-pin --from-literal=pin="$(rndpin hsm-pin-party-$n)" --dry-run=client -o yaml | k apply -f - >/dev/null
  kn "$n" create secret generic qv-party-hsm-so-pin --from-literal=so-pin="$(rndpin hsm-so-party-$n)" --dry-run=client -o yaml | k apply -f - >/dev/null
done
PA="$(pin $NS_SIGN qv-signing-mpc-party-a-tls)"; PB="$(pin $NS_B qv-signing-mpc-party-b-tls)"; PC="$(pin $NS_C qv-signing-mpc-party-c-tls)"
GW="$(pin $NS_SIGN qv-signing-gateway-party-tls)"
addr_b="qv-party-b-peer.$NS_B.svc:7003"; addr_c="qv-party-c-peer.$NS_C.svc:7003"
GWSEL="{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $NS_SIGN } }, podSelector: { matchLabels: { app.kubernetes.io/component: gateway } } }"
common() { cat <<Y
adminKeys: [$ADMIN_KEYS]
adminThreshold: 2
hsm: { pinSecret: qv-party-hsm-pin, softhsm: { enabled: true, soPinSecret: qv-party-hsm-so-pin } }
Y
}
{ common; cat <<Y
role: A
callerPins: ["$GW"]
peers: { b: { address: "$addr_b", pins: ["$PB"] }, c: { address: "$addr_c", pins: ["$PC"] } }
network:
  callerIngress: { from: [ $GWSEL ] }
  peerEgress: { to: [ $(sel $NS_B), $(sel $NS_C) ] }
Y
} > "$WORK/party-a.yaml"
for r in B C; do
  l="$(echo $r | tr A-Z a-z)"; ns="$NS_B"; [ "$r" = C ] && ns="$NS_C"
  SOCK="$(pin $ns qv-signing-cosigner-socket-tls)"; ME="$(pin $ns qv-signing-mpc-party-$l-tls)"
  if [ "$r" = B ]; then
    peers="peers: { a: { pins: [\"$PA\"] }, c: { address: \"$addr_c\", pins: [\"$PC\"] } }"
    pin_in="$(sel $NS_SIGN)"; pe="peerEgress: { to: [ $(sel $NS_C) ] }"
  else
    peers="peers: { a: { pins: [\"$PA\"] }, b: { pins: [\"$PB\"] } }"
    pin_in="$(sel $NS_SIGN), $(sel $NS_B)"; pe=""
  fi
  { common; cat <<Y
role: $r
callerPins: ["$GW"]
$peers
cosigner:
  config: { chains: [], approvers: [] }
  socketPins: ["$SOCK"]
  partyPins: ["$ME"]
  database: { host: qv-guard-rw, port: 5432, name: qv_cosigner_guard, role: qv_cosigner_${l}_guard }
  kafka: { brokers: "redpanda.$NS_BIZ.svc:9092" }
network:
  callerIngress: { from: [ $GWSEL ] }
  peerIngress: { from: [ $pin_in ] }
  $pe
  guardDatabase: { to: [ { podSelector: { matchLabels: { cnpg.io/cluster: qv-guard } } } ], ports: [5432] }
  kafka: { to: [ { namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $NS_BIZ } }, podSelector: { matchLabels: { app.kubernetes.io/name: redpanda } } } ], ports: [9092] }
Y
  } > "$WORK/party-$l.yaml"
done
# The cosigner's own copy of the signing config. First the repository's example (it parses; every key in it is a placeholder), so that the pods start and the DKG can run; charts.sh
# upgrades B and C with the real one (approvers, hot addresses from the DKG) through COSIGNER_CONFIG.
COSIGNER_CONFIG="${COSIGNER_CONFIG:-}"
if [ -n "$COSIGNER_CONFIG" ]; then src="$COSIGNER_CONFIG"; else src=internal/gateway/config.example.json; fi
jq '{cosigner:{config:(del(._comment))}}' "$src" > "$WORK/cosigner-config.yaml"
rel() { # role ns
  hm upgrade --install "qv-party-$1" deploy/helm/qv-party -n "$2" --set role="$(echo $1 | tr a-z A-Z)" -f deploy/helm/qv-party/values-kind.yaml $(trust_args "$2") -f "$WORK/party-$1.yaml" $( [ "$1" != a ] && echo "-f $WORK/cosigner-config.yaml" ) --wait --timeout 6m >/dev/null
}
rel c "$NS_C" & pc=$!
rel b "$NS_B" & pb=$!
rel a "$NS_SIGN" & pa=$!
wait_all "$pa" "$pb" "$pc"
log "parties ready"
