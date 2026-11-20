#!/usr/bin/env bash
# Case 4: NetworkPolicy. Needs a CNI that enforces (kindnet in kind v0.33 does; this case proves it first with a control pair).
#  - an unlisted pod cannot reach Postgres, a listed one (core) can
#  - a pod of the business namespace cannot reach a signing namespace; a signing pod cannot reach the internet   (signing parts need the signing namespaces' pods: skipped until installed)
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"; set +e
rc=0; bad() { echo "FAIL: $*"; rc=1; }
img=nginx:1.27-alpine
probe() { # ns label host port -> 0 when the TCP connect works. A throw-away pod with the given labels.
  local ns="$1" labels="$2" host="$3" port="$4" name="probe-$RANDOM"
  k -n "$ns" run "$name" --image=$img --image-pull-policy=IfNotPresent --restart=Never --labels="$labels" --command -- sh -c "nc -z -w 3 $host $port && echo OPEN || echo CLOSED" >/dev/null
  for _ in $(seq 60); do ph="$(k -n "$ns" get pod "$name" -o jsonpath='{.status.phase}')"; [ "$ph" = Succeeded ] || [ "$ph" = Failed ] && break; sleep 1; done
  out="$(k -n "$ns" logs "$name" 2>/dev/null)"; k -n "$ns" delete pod "$name" --wait=false >/dev/null
  [ "$out" = OPEN ]
}
dbip="$(kn "$NS_BIZ" get svc qv-business-db-rw -o jsonpath='{.spec.clusterIP}')"
# the unlisted pod needs DNS only if it uses a name: use the Service address, and the control: a pod the chart lists (core's labels) reaches it
probe "$NS_BIZ" "app.kubernetes.io/name=qv,app.kubernetes.io/instance=qv-business,app.kubernetes.io/component=core" "$dbip" 5432 || bad "control: a listed pod (core's labels) cannot reach Postgres: the policy test would prove nothing"
probe "$NS_BIZ" "app=intruder" "$dbip" 5432 && bad "an unlisted pod reached Postgres"
if kn "$NS_SIGN" get pod -l app.kubernetes.io/name=qv-party -o name 2>/dev/null | grep -q .; then
  sig="$(kn "$NS_SIGN" get pod -l app.kubernetes.io/name=qv-party -o jsonpath='{.items[0].status.podIP}')"
  probe "$NS_BIZ" "app.kubernetes.io/name=qv,app.kubernetes.io/instance=qv-business,app.kubernetes.io/component=core" "$sig" 7001 && bad "a business pod reached a signing pod"
  probe "$NS_SIGN" "app.kubernetes.io/name=qv-party" 1.1.1.1 443 && bad "a signing pod reached the internet"
else
  echo "signing namespaces have no pods yet: the business->signing and signing->internet checks are pending (README Status)"
fi
exit $rc
