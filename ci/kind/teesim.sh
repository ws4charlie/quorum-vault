#!/usr/bin/env bash
# The tee-sim case of the kind lane (task Broker-chart): a SIMULATED enclave. Replaces the three parties of the lane by parties in attested mode, each with its own attestation broker in its own namespace
# (qv-broker-a|b|c), runs the enrolment Jobs (sealed TLS keys), signs the allowlists (the lane plays the operators), starts the parties and makes a DKG through party A.
# DESTRUCTIVE: it uninstalls qv-party-a|b|c and deletes their data volumes (new keys, the keys of the other cases are gone). smoke/run.sh runs it last. Idempotent from the start (it cleans first).
# Nothing here proves isolation: the evidence is a mock document signed by a test CA. It proves that the charts, the Jobs and the phases do what the runbook says in a real cluster.
# Operator work the lane does from the host (docker run of the tee-sim tools, kubectl, helm) is what an operator does with the same commands (docs/runbooks/tee-broker.md, "On Kubernetes").
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$QV_KIND_ROOT"
T="$WORK/tee"; S="$WORK/secrets"
PARTY_IMG="qv-image/mpc-party-teesim:local"; BROKER_IMG="qv-image/qv-attest-broker-teesim:local"
roles="a b c"
ns_of() { case "$1" in a) echo "$NS_SIGN";; b) echo "$NS_B";; c) echo "$NS_C";; esac; }
upper() { echo "$1" | tr a-z A-Z; }
sel() { echo "{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $1 } } }"; }
spki_pin() { openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex | awk '{print $NF}'; }
dk() { docker run --rm --user "$(id -u):$(id -g)" -v "$T:/w" "$@"; }
rndpin() { [ -s "$S/$1" ] || ( umask 077; openssl rand -hex 8 | tr a-f 0-5 > "$S/$1" ); cat "$S/$1"; }
sha10() { openssl dgst -sha256 -hex "$1" | awk '{print substr($NF,1,10)}'; }
fresh_dir() { rm -rf "${T:?}" && mkdir -p "$T" && chmod 777 "$T"; }

log "tee-sim: images"
if [ "${QV_KIND_SKIP_BUILD:-}" != 1 ]; then QV_IMAGE_PREFIX=qv-image/ QV_IMAGE_TAG=local deploy/images/build.sh mpc-party-teesim qv-attest-broker-teesim >&2; fi
load_images "$PARTY_IMG" "$BROKER_IMG"

log "tee-sim: remove the pkcs11 parties and their data (this case makes new keys)"
for r in $roles; do
  hm -n "$(ns_of $r)" uninstall "qv-party-$r" >/dev/null 2>&1 || true
  kn "$(ns_of $r)" delete pvc "data-qv-party-$r-0" --ignore-not-found --wait=true >/dev/null
  hm -n "qv-broker-$r" uninstall "qv-tee-broker-$r" >/dev/null 2>&1 || true
  kn "qv-broker-$r" delete pvc --all --ignore-not-found >/dev/null 2>&1 || true
done
fresh_dir

log "tee-sim: the test CA, three operator keys, certificates, Secrets"
dk --entrypoint /usr/local/bin/qv-attest-ca "$PARTY_IMG" -dir /w/ca >/dev/null
OPS=""
for n in alice bob carol; do
  dk --entrypoint /usr/local/bin/qv-attest-broker "$BROKER_IMG" allowlist keygen -key "/w/op-$n.key" -pub "/w/op-$n.pub" >/dev/null
  OPS="$OPS    $n: \"$(tr -d '[:space:]' < "$T/op-$n.pub" | sed 's/^publickey://; s/^public key://')\"
"
done
ROOTCM="qv-attest-evidence-root-$(sha10 "$T/ca/root.crt")"
selfsigned() { # dir cn san: a self-signed certificate; the pin is the check
  openssl ecparam -name prime256v1 -genkey -noout -out "$1/tls.key" 2>/dev/null   # SEC1 key without the parameters block (macOS openssl writes one with `req -newkey ec`, which Go refuses)
  openssl req -x509 -new -key "$1/tls.key" -days 30 -subj "/CN=$2" -addext "subjectAltName=DNS:$3" -out "$1/tls.crt" 2>/dev/null
}
vv() { eval "printf %s \"\${$1_$2}\""; }   # vv NAME role: the per-role value (bash 3.2 on macOS has no associative arrays)
for r in $roles; do
  ns="$(ns_of $r)"; bns="qv-broker-$r"
  k create namespace "$bns" --dry-run=client -o yaml | k apply -f - >/dev/null
  mkdir -p "$T/bs-$r" "$T/ls-$r"
  selfsigned "$T/bs-$r" "qv-tee-broker-$r" "qv-tee-broker-$r.$bns.svc"
  selfsigned "$T/ls-$r" "party-$r-broker-link" "party-$r"
  eval "BPIN_$r=$(spki_pin < "$T/bs-$r/tls.crt")"; eval "LPIN_$r=$(spki_pin < "$T/ls-$r/tls.crt")"
  kn "$bns" create secret generic "qv-attest-broker-$r-tls" --from-file=tls.crt="$T/bs-$r/tls.crt" --from-file=tls.key="$T/bs-$r/tls.key" --dry-run=client -o yaml | k apply -f - >/dev/null
  kn "$ns" create secret generic "mpc-party-$r-broker-link-tls" --from-file=tls.crt="$T/ls-$r/tls.crt" --from-file=tls.key="$T/ls-$r/tls.key" --dry-run=client -o yaml | k apply -f - >/dev/null
  kn "$bns" create secret generic qv-attest-broker-hsm-pin --from-literal=pin="$(rndpin brk-pin-$r)" --dry-run=client -o yaml | k apply -f - >/dev/null
  kn "$bns" create secret generic qv-attest-broker-hsm-so-pin --from-literal=so-pin="$(rndpin brk-so-$r)" --dry-run=client -o yaml | k apply -f - >/dev/null
  kn "$ns" create secret generic qv-tee-ca --from-file=root.crt="$T/ca/root.crt" --from-file=intermediate.crt="$T/ca/intermediate.crt" --from-file=intermediate.key="$T/ca/intermediate.key" --dry-run=client -o yaml | k apply -f - >/dev/null
  # the evidence root: public, immutable, named with the hash of the file (the cluster policy's rule)
  kn "$bns" create configmap "$ROOTCM" --from-file=root.pem="$T/ca/root.crt" --dry-run=client -o json | jq '. + {immutable: true}' | k apply -f - >/dev/null
done

# ---- the brokers and their allowlists: the sequence number rises with each list; two of three operators sign
SEQ=0
install_brokers() { # entries "ROLE:measurement-hex"; a role without an entry gets the "nothing allowed" measurement
  SEQ=$((SEQ+1)); local r m e nb na
  nb="$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '-1 hour' +%Y-%m-%dT%H:%M:%SZ)"
  na="$(date -u -v+2d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+2 days' +%Y-%m-%dT%H:%M:%SZ)"
  for r in $roles; do
    m="$(printf '11%.0s' $(seq 48))"
    for e in "$@"; do if [ "${e%%:*}" = "$(upper $r)" ]; then m="${e#*:}"; fi; done
    rm -f "$T/list-$r.json"
    dk --entrypoint /usr/local/bin/qv-attest-broker "$BROKER_IMG" allowlist new -seq "$SEQ" -out "/w/list-$r.json" -entry "$(upper $r),$m,$nb,$na" >/dev/null
    for n in alice bob; do dk --entrypoint /usr/local/bin/qv-attest-broker "$BROKER_IMG" allowlist sign -in "/w/list-$r.json" -key "/w/op-$n.key" -operator "$n" >/dev/null; done
    cat > "$T/broker-$r.yaml" <<Y
party: { role: $(upper $r), callerPins: ["$(vv LPIN $r)"] }
operators:
  minOperators: 2
  keys:
$OPS
trustRoots: { configMap: $ROOTCM }
network: { partyIngress: { from: [ $(sel "$(ns_of $r)") ] } }
Y
    hm upgrade --install "qv-tee-broker-$r" deploy/helm/qv-attest-broker -n "qv-broker-$r" -f deploy/helm/qv-attest-broker/values.yaml -f deploy/helm/qv-attest-broker/values-kind.yaml \
      -f "$T/broker-$r.yaml" --set-file allowlist.file="$T/list-$r.json" --wait --timeout 4m >/dev/null &
    eval "bp_$r=$!"
  done
  wait_all "$bp_a" "$bp_b" "$bp_c"
}
log "tee-sim: brokers (nothing allowed yet)"
install_brokers

# ---- party values
ADMIN_PUB="$(go run ./ci/kind/tools/kindctl adminkey -seed "$S/admin.seed")"
GW="$(kn "$NS_SIGN" get secret qv-signing-gateway-party-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | spki_pin)"
GWSEL="{ namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $NS_SIGN } }, podSelector: { matchLabels: { app.kubernetes.io/component: gateway } } }"
attested_values() { # role: what every phase needs
  local r="$1"
  cat <<Y
role: $(upper $r)
attested:
  broker: { url: "https://qv-tee-broker-$r.qv-broker-$r.svc:8443", pins: ["$(vv BPIN $r)"] }
  attester: { type: mock, mock: { caSecret: qv-tee-ca } }
Y
}
party_chart() { echo "deploy/helm/qv-party -n $(ns_of $1) -f deploy/helm/qv-party/values.yaml -f deploy/helm/qv-party/values-kind.yaml -f deploy/helm/qv-party/values-kind-teesim.yaml"; }
tmpl_file() { # role key out helm-args...: the bytes of one ConfigMap file, from the render (what the pod will mount), written to $T/<out>
  local r="$1" key="$2" out="$3"; shift 3
  # shellcheck disable=SC2046
  helm template "qv-party-$r" $(party_chart "$r") "$@" | kubectl create --dry-run=client -o json -f - 2>/dev/null | jq -rj --arg k "$key" 'select(.kind=="ConfigMap") | .data[$k] // empty' > "$T/$out"
  [ -s "$T/$out" ] || { echo "no $key in the render" >&2; return 1; }
}
measure() { dk --entrypoint /usr/local/bin/qv-attest-ca "$PARTY_IMG" measure -binary /usr/local/bin/mpc-party -config "/w/$1"; }
brokernet() { echo "network: { broker: { to: [ $(sel "qv-broker-$1") ], ports: [8443] } }"; }

log "tee-sim: enrolment (the allowlist holds the enrolment measurements only while it runs)"
ENT=()
for r in $roles; do
  { attested_values "$r"; brokernet "$r"; } > "$T/att-$r.yaml"
  tmpl_file "$r" enroll.json "enroll-$r.json" -f "$T/att-$r.yaml" --set attested.phase=enrol --set attested.stopPartyAck=true
  ENT+=("$(upper $r):$(measure "enroll-$r.json")")
done
install_brokers "${ENT[@]}"
for r in $roles; do
  # shellcheck disable=SC2046
  hm upgrade --install "qv-party-$r" $(party_chart $r) -f "$T/att-$r.yaml" --set attested.phase=enrol --set attested.stopPartyAck=true >/dev/null
done
for r in $roles; do
  kn "$(ns_of $r)" wait --for=condition=complete "job/qv-party-$r-enrol-manual" --timeout=240s >/dev/null || { kn "$(ns_of $r)" logs "job/qv-party-$r-enrol-manual" | tail -20 >&2; exit 1; }
  eval "PIN_$r=$(kn "$(ns_of $r)" logs "job/qv-party-$r-enrol-manual" 2>/dev/null | grep -E '^[0-9a-f]{64}$' | tail -1)"
  [ -n "$(vv PIN $r)" ] || { echo "no pin in the enrolment log of $r" >&2; exit 1; }
  echo "party $(upper $r) sealed TLS pin $(vv PIN $r)"
done

log "tee-sim: the running configs, their measurements, then the parties"
sockpin() { kn "$1" get secret qv-signing-cosigner-socket-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | spki_pin; }
jq '{cosigner:{config:(del(._comment))}}' internal/gateway/config.example.json > "$T/cosigner-config.yaml"
run_values() { # role
  local r="$1"
  attested_values "$r"
  cat <<Y
adminKeys: ["$ADMIN_PUB"]
callerPins: ["$GW"]
Y
  case "$r" in
  a) cat <<Y
peers: { b: { address: "qv-party-b-peer.$NS_B.svc:7003", pins: ["$(vv PIN b)"] }, c: { address: "qv-party-c-peer.$NS_C.svc:7003", pins: ["$(vv PIN c)"] } }
network:
  broker: { to: [ $(sel qv-broker-a) ], ports: [8443] }
  callerIngress: { from: [ $GWSEL ] }
  peerEgress: { to: [ $(sel $NS_B), $(sel $NS_C) ] }
Y
  ;;
  b|c)
    local peers pin_in pe=""
    if [ "$r" = b ]; then peers="peers: { a: { pins: [\"$(vv PIN a)\"] }, c: { address: \"qv-party-c-peer.$NS_C.svc:7003\", pins: [\"$(vv PIN c)\"] } }"; pin_in="$(sel $NS_SIGN)"; pe="peerEgress: { to: [ $(sel $NS_C) ] }"
    else peers="peers: { a: { pins: [\"$(vv PIN a)\"] }, b: { pins: [\"$(vv PIN b)\"] } }"; pin_in="$(sel $NS_SIGN), $(sel $NS_B)"; fi
    cat <<Y
$peers
cosigner:
  config: { chains: [], approvers: [] }
  socketPins: ["$(sockpin "$(ns_of $r)")"]
  partyPins: ["$(vv PIN $r)"]
  database: { host: qv-guard-rw, port: 5432, name: qv_cosigner_guard, role: qv_cosigner_guard }
  kafka: { brokers: "redpanda.$NS_BIZ.svc:9092" }
network:
  broker: { to: [ $(sel qv-broker-$r) ], ports: [8443] }
  callerIngress: { from: [ $GWSEL ] }
  peerIngress: { from: [ $pin_in ] }
  $pe
  guardDatabase: { to: [ { podSelector: { matchLabels: { cnpg.io/cluster: qv-guard } } } ], ports: [5432] }
  kafka: { to: [ { namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $NS_BIZ } }, podSelector: { matchLabels: { app.kubernetes.io/name: redpanda } } } ], ports: [9092] }
Y
  ;;
  esac
}
RUN=()
for r in $roles; do
  run_values "$r" > "$T/run-$r.yaml"
  extra=(-f "$T/run-$r.yaml" $(trust_args "$(ns_of $r)")); if [ "$r" != a ]; then extra+=(-f "$T/cosigner-config.yaml"); fi
  tmpl_file "$r" party.json "party-$r.json" "${extra[@]}"
  RUN+=("$(upper $r):$(measure "party-$r.json")")
done
install_brokers "${RUN[@]}"        # the enrolment entries are revoked: only the running measurements are allowed now
for r in $roles; do
  extra=(-f "$T/run-$r.yaml" $(trust_args "$(ns_of $r)")); if [ "$r" != a ]; then extra+=(-f "$T/cosigner-config.yaml"); fi
  # shellcheck disable=SC2046
  hm upgrade --install "qv-party-$r" $(party_chart $r) "${extra[@]}" --wait --timeout 6m >/dev/null &
  eval "pp_$r=$!"
done
wait_all "$pp_a" "$pp_b" "$pp_c"
log "tee-sim: parties ready"

log "tee-sim: DKG through party A (keys released by three brokers, sealed TLS between the parties)"
g() { kn "$NS_SIGN" get secret qv-signing-gateway-party-tls -o jsonpath="{.data.$1}" | base64 -d; }
g 'tls\.crt' > "$WORK/gwp.crt"; ( umask 077; g 'tls\.key' > "$WORK/gwp.key" )
trap pf_stop EXIT
pf_start "$NS_SIGN" svc/qv-party-a-caller 7001
retry() { local i; for i in 1 2 3 4 5 6; do "$@" && return 0; sleep 10; done; return 1; }
retry go run ./ci/kind/tools/kindctl dkg -addr "127.0.0.1:$PF_PORT" -cert "$WORK/gwp.crt" -key "$WORK/gwp.key" -pin "$(vv PIN a)" -id tee-0 -seed "$S/admin.seed" -scheme ecdsa-2of3 > "$T/tee-0.json"
echo "tee-sim DKG: $(cat "$T/tee-0.json")"
for r in $roles; do printf '%s\n' "$(vv PIN $r)" > "$T/pin-$r"; done
log "tee-sim: done"
