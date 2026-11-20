#!/usr/bin/env bash
# Case (design item 4): certificates in the real pods.
#   1. rotation WITHOUT restart: the core's certificate Secret is deleted, cert-manager issues a new one, and the SAME pod (same uid, no restart) serves the new certificate after kubelet
#      refreshes the mounted files and the service re-reads them (QV_TLS_RELOAD, 1 minute), still trusted by the authority.
#   2. an EXPIRED certificate refuses start: the core's own pod template, with its certificate replaced by one that expired two days ago (the same authority), exits with the expiry message.
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"; set +e
cd "$QV_KIND_ROOT"
rc=0; bad() { echo "FAIL: $*"; rc=1; }
S="$WORK/secrets"
trap 'pf_stop; kn "$NS_BIZ" delete pod qv-core-expired --wait=false >/dev/null 2>&1; kn "$NS_BIZ" delete secret qv-core-tls-expired >/dev/null 2>&1' EXIT
core_pod() { kn "$NS_BIZ" get pod -l app.kubernetes.io/component=core --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'; }
serial() { # the serial of the certificate the core serves now
  pf_start "$NS_BIZ" "pod/$1" 8443 || return 1
  echo | openssl s_client -connect "127.0.0.1:$PF_PORT" -servername qv-core.qv.svc -CAfile "$S/ca-business.crt" -verify_return_error 2>/dev/null | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2
  pf_stop
}

echo "-- rotation without restart"
kn "$NS_BIZ" rollout status deploy/qv-business-core --timeout=120s >/dev/null
pod="$(core_pod)"; uid="$(kn "$NS_BIZ" get pod "$pod" -o jsonpath='{.metadata.uid}')"; r0="$(kn "$NS_BIZ" get pod "$pod" -o jsonpath='{.status.containerStatuses[0].restartCount}')"
s0="$(serial "$pod")"; [ -n "$s0" ] || bad "the core does not serve a certificate the authority trusts"
echo "pod $pod serves $s0"
kn "$NS_BIZ" delete secret qv-core-tls >/dev/null || bad "could not delete the secret"
s1="$s0"
for i in $(seq 60); do
  sleep 6; s1="$(serial "$pod")"; [ -n "$s1" ] && [ "$s1" != "$s0" ] && break
done
[ -n "$s1" ] && [ "$s1" != "$s0" ] && echo "pod $pod serves $s1 now ($(( i * 6 )) s)" || bad "the pod still serves the old certificate ($s0) after 6 minutes"
[ "$(kn "$NS_BIZ" get pod "$pod" -o jsonpath='{.metadata.uid}')" = "$uid" ] || bad "the pod was replaced"
[ "$(kn "$NS_BIZ" get pod "$pod" -o jsonpath='{.status.containerStatuses[0].restartCount}')" = "$r0" ] || bad "the container restarted"

echo "-- an expired certificate refuses start"
d="$(mktemp -d)"; chmod 700 "$d"
go run ./ci/kind/tools/kindcert expired -ca-crt "$S/ca-business.crt" -ca-key "$S/ca-business.key" -out "$d" || bad "could not make the certificate"
kn "$NS_BIZ" create secret generic qv-core-tls-expired --from-file=tls.crt="$d/tls.crt" --from-file=tls.key="$d/tls.key" --from-file=ca.crt="$d/ca.crt" >/dev/null; rm -rf "$d"
kn "$NS_BIZ" get deploy qv-business-core -o json | jq --arg n qv-core-tls-expired \
  '{apiVersion:"v1",kind:"Pod",metadata:{name:"qv-core-expired",namespace:"qv",labels:.spec.template.metadata.labels},spec:(.spec.template.spec|.restartPolicy="Never"|walk(if type=="string" and .=="qv-core-tls" then $n else . end))}' | k apply -f - >/dev/null || bad "could not start the pod"
kn "$NS_BIZ" wait --for=jsonpath='{.status.phase}'=Failed pod/qv-core-expired --timeout=180s >/dev/null || bad "the pod with the expired certificate did not fail: $(kn "$NS_BIZ" get pod qv-core-expired -o jsonpath='{.status.phase}')"
out="$(kn "$NS_BIZ" logs qv-core-expired 2>&1)"
grep -qi "expired" <<< "$out" && echo "refused: $(grep -i expired <<< "$out" | head -1 | cut -c1-200)" || bad "it failed, but not on the certificate: $out"
exit $rc
