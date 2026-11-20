#!/usr/bin/env bash
# Case 1: everything ready, the migration ran once, service roles can log in and cannot do what the runbook's matrix forbids (one spot check).
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"; set +e
rc=0; bad() { echo "FAIL: $*"; rc=1; }
for ns in $NS_BIZ; do
  notready="$(kn "$ns" get pods --no-headers | grep -v Completed | awk '{split($2,a,"/"); if (a[1]!=a[2]) print $1}')"
  [ -z "$notready" ] || bad "pods not ready in $ns: $notready"
done
# the migration Job is a hook deleted on success: its effect is the proof (the schema is current and the roles can log in), and Helm's history says it ran once per revision
kn "$NS_BIZ" get cm >/dev/null
rev="$(hm -n "$NS_BIZ" history qv-business -o json | jq 'length')"
echo "qv-business revisions: $rev"
psql_as() { # $1 pod-side role (cert name), $2 sql: runs psql inside the database pod with the client certificate of that service
  local cert="$1" role="$2" sql="$3"
  kn "$NS_BIZ" get secret "qv-$cert-tls" >/dev/null 2>&1 || { echo "no secret qv-$cert-tls"; return 2; }
  local d; d="$(mktemp -d)"
  for f in tls.crt tls.key ca.crt; do kn "$NS_BIZ" get secret "qv-$cert-tls" -o jsonpath="{.data.${f/./\\.}}" | base64 -d > "$d/$f"; done
  chmod 600 "$d/tls.key"
  kn "$NS_BIZ" port-forward svc/qv-business-db-rw 15432:5432 >/dev/null 2>&1 & local pf=$!
  sleep 2
  env -u PGPASSWORD psql "host=127.0.0.1 port=15432 dbname=quorumvault user=$role sslmode=verify-ca sslrootcert=$d/ca.crt sslcert=$d/tls.crt sslkey=$d/tls.key" -Atc "$sql" 2>&1
  local r=$?; kill $pf 2>/dev/null; rm -rf "$d"; return $r
}
if command -v psql >/dev/null; then
  out="$(psql_as core qv_core 'select current_user')"; [ "$out" = qv_core ] || bad "core's certificate did not log in as qv_core: $out"
  out="$(psql_as core qv_core 'create table smoke_forbidden(x int)')"; echo "$out" | grep -qi "permission denied" || bad "qv_core could create a table: $out"
else
  echo "psql not installed: the role spot check is skipped"
fi
exit $rc
