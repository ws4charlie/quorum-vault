#!/usr/bin/env bash
# Phase 2 of `make kind-up`: generated secrets, certificates (qv-certs per namespace), the dependencies, the four charts. Idempotent.
#   ci/kind/install.sh [secrets|certs|deps|charts|all]
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$QV_KIND_ROOT"
PHASE="${1:-all}"
S="$WORK/secrets"; mkdir -p "$S"; chmod 700 "$S"
rnd() { openssl rand -hex "${1:-16}"; }
# kept across runs of one cluster: a value is made once and then read back
val() { local f="$S/$1"; [ -s "$f" ] || { umask 077; rnd "${2:-16}" > "$f"; }; cat "$f"; }

phase_secrets() {
  log "secrets: two authorities, passwords, keys (all in $WORK, gitignored)"
  local z
  for z in business signing; do
    if [ ! -s "$S/ca-$z.key" ]; then
      ( umask 077
        openssl ecparam -name prime256v1 -genkey -noout -out "$S/ca-$z.key"
        openssl req -x509 -new -key "$S/ca-$z.key" -subj "/CN=quorumvault-$z-ca" -days 3650 -out "$S/ca-$z.crt" \
          -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" ) 2>/dev/null
    fi
  done
  # The one authority per zone, copied into every namespace that issues under it (qv-certs issuers.ca.existing). The business authority's key also goes to the signing
  # namespaces, because the link certificates (gateway-link, cosigner-link) are signed by it: development only, the README says so.
  kcreate_tls() { k -n "$1" create secret tls "$2" --cert="$S/ca-$3.crt" --key="$S/ca-$3.key" --dry-run=client -o yaml | k apply -f - >/dev/null; }
  kcreate_tls "$NS_BIZ" qv-business-ca business
  for n in $NS_SIGN $NS_B $NS_C; do kcreate_tls "$n" qv-signing-ca signing; kcreate_tls "$n" qv-business-ca business; done
  # passwords and keys of the dependencies
  kn "$NS_BIZ" create secret generic keycloak-env --dry-run=client -o yaml \
    --from-literal=KC_BOOTSTRAP_ADMIN_PASSWORD="$(val kc-admin)" --from-literal=QV_TEST_PASSWORD_ALICE="$(val kc-alice)" --from-literal=QV_TEST_PASSWORD_BOB="$(val kc-bob)" \
    --from-literal=QV_TEST_PASSWORD_CAROL="$(val kc-carol)" --from-literal=QV_TEST_PASSWORD_OPS="$(val kc-ops)" --from-literal=QV_KEYCLOAK_GUARDIAN_SECRET="$(val kc-guardian)" | k apply -f - >/dev/null
  kn "$NS_BIZ" create secret generic seaweedfs-env --dry-run=client -o yaml \
    --from-literal=ROOT_AK="$(val s3-root-ak 10)" --from-literal=ROOT_SK="$(val s3-root-sk 20)" --from-literal=ARC_AK="$(val s3-arc-ak 10)" --from-literal=ARC_SK="$(val s3-arc-sk 20)" | k apply -f - >/dev/null
  kn "$NS_BIZ" create secret generic qv-archive-credentials --dry-run=client -o yaml \
    --from-literal=access-key="$(val s3-arc-ak 10)" --from-literal=secret-key="$(val s3-arc-sk 20)" | k apply -f - >/dev/null
  kn "$NS_BIZ" create secret generic chain-credentials --dry-run=client -o yaml \
    --from-literal=BTC_RPC_USER="qv$(val btc-user 4)" --from-literal=BTC_RPC_PASSWORD="$(val btc-pass 20)" | k apply -f - >/dev/null
  # HSM PIN and security-officer PIN of the gateway's SoftHSM token (signing-core values-kind names the Secret)
  kn "$NS_SIGN" create secret generic qv-gateway-hsm-pin --dry-run=client -o yaml \
    --from-literal=pin="$(val hsm-pin 8 | tr a-f 0-5 | cut -c1-12)" --from-literal=so-pin="$(val hsm-so-pin 8)" | k apply -f - >/dev/null
}

# DNS names the clients dial, per catalog name, per namespace (qv-certs extraDNSNames)
dns_values() {
  local ns="$1" f="$WORK/certs-$1.yaml"
  case "$ns" in
    "$NS_BIZ") cat > "$f" <<Y
extraDNSNames:
  postgres: [qv-business-db-rw, qv-business-db-rw.$NS_BIZ, qv-business-db-rw.$NS_BIZ.svc, qv-business-db-rw.$NS_BIZ.svc.cluster.local]
  temporal-db: [qv-temporal-db-rw, qv-temporal-db-rw.$NS_BIZ.svc]
  kafka: [redpanda.$NS_BIZ, redpanda.$NS_BIZ.svc, redpanda.$NS_BIZ.svc.cluster.local]
  temporal: [temporal-gate, temporal-gate.$NS_BIZ.svc]
  keycloak: [keycloak.$NS_BIZ.svc]
  seaweedfs: [seaweedfs.$NS_BIZ.svc]
  core: [qv-core.$NS_BIZ.svc]
Y
    ;;
    "$NS_SIGN") cat > "$f" <<Y
extraDNSNames:
  signing-db: [qv-guard-rw, qv-guard-rw.$NS_SIGN.svc]
  mpc-party-a: [qv-party-a, qv-party-a.$NS_SIGN.svc]
Y
    ;;
    "$NS_B") cat > "$f" <<Y
extraDNSNames:
  signing-db: [qv-guard-rw, qv-guard-rw.$NS_B.svc]
  mpc-party-b: [qv-party-b, qv-party-b.$NS_B.svc]
Y
    ;;
    "$NS_C") cat > "$f" <<Y
extraDNSNames:
  signing-db: [qv-guard-rw, qv-guard-rw.$NS_C.svc]
  mpc-party-c: [qv-party-c, qv-party-c.$NS_C.svc]
Y
    ;;
  esac
}

phase_certs() {
  log "certificates: qv-certs in each namespace, all under the same two authorities"
  local pair ns cluster
  for pair in "$NS_BIZ:business" "$NS_SIGN:signing-core" "$NS_B:party-b" "$NS_C:party-c"; do
    ns="${pair%%:*}"; cluster="${pair##*:}"
    dns_values "$ns"
    hm upgrade --install qv-certs deploy/helm/qv-certs -n "$ns" -f deploy/helm/qv-certs/values-kind.yaml -f "$WORK/certs-$ns.yaml" \
      --set cluster="$cluster" --set issuers.ca.existing=true --set trust.allowEmpty=false \
      --set-file trust.business="$S/ca-business.crt" --set-file trust.signing="$S/ca-signing.crt" >/dev/null
  done
  for ns in $ALL_NS; do kn "$ns" wait certificate --all --for=condition=Ready --timeout=180s >/dev/null; done
}

# One CloudNativePG cluster: the same pg_hba/pg_ident files as compose (deploy/postgres/*), TLS 1.3 and client certificates only. Arguments: namespace name database owner
# server-certificate-Secret issuer ident-file [extra bootstrap SQL]
pg_cluster() {
  local ns="$1" name="$2" db="$3" owner="$4" srv="$5" issuer="$6" ident="$7" sql="${8:-}"
  local idents; idents="$(grep -vE '^\s*(#|$)' "$ident" | sed 's/^/        - /')"
  cat <<Y
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: $name-replication, namespace: $ns }
spec:
  secretName: $name-replication
  commonName: streaming_replica
  usages: [client auth]
  issuerRef: { name: $issuer, kind: Issuer, group: cert-manager.io }
---
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata: { name: $name, namespace: $ns }
spec:
  instances: 1
  imageName: ghcr.io/cloudnative-pg/postgresql:16.10
  imagePullPolicy: IfNotPresent
  storage: { size: 1Gi }
  resources: { requests: { cpu: 100m, memory: 192Mi }, limits: { memory: 512Mi } }
  bootstrap:
    initdb:
      database: $db
      owner: $owner
$( [ -n "$sql" ] && printf '      postInitSQL:\n        - %s\n' "$sql" )
  certificates:
    serverTLSSecret: $srv
    serverCASecret: $srv
    clientCASecret: $srv
    replicationTLSSecret: $name-replication
  postgresql:
    parameters:
      ssl_min_protocol_version: TLSv1.3
    pg_hba:
      - hostnossl all all all reject
      - hostssl all all all cert map=qv
    pg_ident:
$idents
Y
}

phase_deps() {
  log "dependencies: Postgres (CloudNativePG), Redpanda, Temporal + gate, Keycloak, SeaweedFS, anvil, bitcoind"
  # databases
  { pg_cluster "$NS_BIZ" qv-business-db quorumvault qv qv-postgres-tls qv-business deploy/postgres/business.pg_ident.conf "ALTER ROLE qv CREATEROLE CREATEDB"
    echo ---
    pg_cluster "$NS_BIZ" qv-temporal-db temporal temporal qv-temporal-db-tls qv-business deploy/postgres/temporal.pg_ident.conf "ALTER ROLE temporal CREATEDB"
  } | k apply -f - >/dev/null
  for ns in $NS_SIGN $NS_B $NS_C; do
    pg_cluster "$ns" qv-guard qv_signing qv qv-signing-signing-db-tls qv-signing deploy/postgres/signing.pg_ident.conf "ALTER ROLE qv CREATEROLE CREATEDB" | k apply -f - >/dev/null
  done
  # the rules the dependency pods need in default-deny namespaces (ci/kind/deps/netpol.sh)
  bash "$KDIR/deps/netpol.sh" "$(docker inspect "$QV_KIND_NAME-control-plane" --format '{{(index .NetworkSettings.Networks "kind").IPAddress}}')" 6443 \
    "$(k -n default get service kubernetes -o jsonpath='{.spec.clusterIP}')" | k apply -f - >/dev/null
  # configuration that is the repository's own files, unchanged
  kn "$NS_BIZ" create configmap redpanda-cfg --from-file=start.sh=deploy/redpanda/start.sh --from-file=acl.sh=deploy/redpanda/acl.sh --dry-run=client -o yaml | k apply -f - >/dev/null
  kn "$NS_BIZ" create configmap temporal-gate-cfg --from-file=start.sh=deploy/temporal-gate/start.sh --dry-run=client -o yaml | k apply -f - >/dev/null
  kn "$NS_BIZ" create configmap temporal-gate-nginx --from-file=nginx.conf=deploy/temporal-gate/nginx.conf --dry-run=client -o yaml | k apply -f - >/dev/null
  kn "$NS_BIZ" create configmap temporal-dynamicconfig --from-literal=dynamicconfig.yaml='{}' --dry-run=client -o yaml | k apply -f - >/dev/null
  kn "$NS_BIZ" create configmap keycloak-realm --from-file=quorumvault-realm.json=deploy/keycloak/quorumvault-realm.json --dry-run=client -o yaml | k apply -f - >/dev/null
  # the gate dials the frontend by the name `temporal`; its upstream and certificate names are the repository's
  for f in redpanda temporal keycloak seaweedfs chains; do k apply -f "$KDIR/deps/$f.yaml" >/dev/null; done
  log "waiting for the dependencies"
  for ns in $NS_BIZ; do
    kn "$ns" wait cluster.postgresql.cnpg.io --all --for=condition=Ready --timeout=300s >/dev/null
  done
  for ns in $NS_SIGN $NS_B $NS_C; do kn "$ns" wait cluster.postgresql.cnpg.io --all --for=condition=Ready --timeout=300s >/dev/null; done
  kn "$NS_BIZ" wait job/temporal-schema --for=condition=complete --timeout=300s >/dev/null
  kn "$NS_BIZ" rollout status statefulset/redpanda deployment/temporal deployment/temporal-gate deployment/keycloak statefulset/seaweedfs deployment/anvil deployment/bitcoind --timeout=300s >/dev/null 2>&1 || \
    { for w in statefulset/redpanda deployment/temporal deployment/temporal-gate deployment/keycloak statefulset/seaweedfs deployment/anvil deployment/bitcoind; do kn "$NS_BIZ" rollout status "$w" --timeout=300s; done; }
}

case "$PHASE" in
  secrets) phase_secrets ;;
  certs)   phase_secrets; phase_certs ;;
  deps)    phase_secrets; phase_certs; phase_deps ;;
  charts)  [ -x "$KDIR/charts.sh" ] && "$KDIR/charts.sh" ;;
  all)     phase_secrets; phase_certs; phase_deps; [ -x "$KDIR/charts.sh" ] && "$KDIR/charts.sh" || true ;;
  *) echo "usage: install.sh [secrets|certs|deps|charts|all]" >&2; exit 2 ;;
esac
