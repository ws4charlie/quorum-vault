#!/usr/bin/env bash
# Phase 3 of `make kind-up`: the real charts with their values-kind.yaml. Generated files (custody config, keys) are in the gitignored work dir; no secret is in a values file.
# Installed so far: qv-business. NOT yet: qv-signing-core and qv-party x3 (README, "Status"): they need the DKG first, see ci/kind/README.md.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$QV_KIND_ROOT"
S="$WORK/secrets"

mk_secret() { local ns="$1" name="$2"; shift 2; kn "$ns" create secret generic "$name" "$@" --dry-run=client -o yaml | k apply -f - >/dev/null; }

log "audit bucket (Object Lock, COMPLIANCE) in SeaweedFS"
trap pf_stop EXIT
pf_start "$NS_BIZ" svc/seaweedfs 8333
g() { kn "$NS_BIZ" get secret "$1" -o jsonpath="{.data.$2}" | base64 -d; }
( umask 077; g qv-admin-tls 'tls\.crt' > "$WORK/admin.crt"; g qv-admin-tls 'tls\.key' > "$WORK/admin.key" )
QV_MKBUCKET_ENDPOINT="https://127.0.0.1:$PF_PORT" QV_MKBUCKET_AK="$(g seaweedfs-env ROOT_AK)" QV_MKBUCKET_SK="$(g seaweedfs-env ROOT_SK)" \
  go run ./ci/kind/tools/mkbucket -cert "$WORK/admin.crt" -key "$WORK/admin.key" -ca "$S/ca-business.crt"
pf_stop

log "qv-business"
# the custody config: the repository's example with the cluster's chain address (rpc credentials would be added here; the example has none)
jq '.chain.rpc_url="http://anvil:8545"' internal/custody/config.example.json > "$S/custody.json"
mk_secret "$NS_BIZ" qv-custody-config --from-file=config.json="$S/custody.json"
[ -s "$S/auto-approver.seed" ] || ( umask 077; openssl rand -hex 32 > "$S/auto-approver.seed" )
mk_secret "$NS_BIZ" qv-auto-approver --from-file=seed="$S/auto-approver.seed"
mk_secret "$NS_BIZ" qv-oidc-ca --from-file=ca.crt="$S/ca-business.crt"
hm upgrade --install qv-business deploy/helm/qv-business -n "$NS_BIZ" -f deploy/helm/qv-business/values-kind.yaml --wait --timeout 6m >/dev/null
log "charts done"
