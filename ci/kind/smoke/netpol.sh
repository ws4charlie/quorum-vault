#!/usr/bin/env bash
# Case 4: NetworkPolicy. Needs a CNI that enforces (kindnet in kind v0.33 does; this case proves it first with a control pair).
#  - an unlisted pod cannot reach Postgres, a listed one (core) can
#  - the signing zone: only the gateway reaches party A's caller port, only the pods the charts list reach a guard database; a business pod reaches no party; party C does not reach A's caller
#    port; neither the gateway nor a party reaches the internet
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"; set +e
rc=0; bad() { echo "FAIL: $*"; rc=1; }
img=nginx:1.27-alpine
probe() { # ns label host port -> 0 when the TCP connect works. A throw-away pod with the given labels. It waits 6 s first: kindnet programs the policy of a new pod a moment AFTER it starts,
  # and a connect in that window gets through (found by the lane: a "blocked" check that passed or failed by luck).
  local ns="$1" labels="$2" host="$3" port="$4" name="probe-$RANDOM"
  k -n "$ns" run "$name" --image=$img --image-pull-policy=IfNotPresent --restart=Never --labels="$labels" --command -- sh -c "sleep 6; nc -z -w 3 $host $port && echo OPEN || echo CLOSED" >/dev/null
  for _ in $(seq 60); do ph="$(k -n "$ns" get pod "$name" -o jsonpath='{.status.phase}')"; [ "$ph" = Succeeded ] || [ "$ph" = Failed ] && break; sleep 1; done
  out="$(k -n "$ns" logs "$name" 2>/dev/null)"; k -n "$ns" delete pod "$name" --wait=false >/dev/null
  [ "$out" = OPEN ]
}
dbip="$(kn "$NS_BIZ" get svc qv-business-db-rw -o jsonpath='{.spec.clusterIP}')"
# the unlisted pod needs DNS only if it uses a name: use the Service address, and the control: a pod the chart lists (core's labels) reaches it
probe "$NS_BIZ" "app.kubernetes.io/name=qv,app.kubernetes.io/instance=qv-business,app.kubernetes.io/component=core" "$dbip" 5432 || bad "control: a listed pod (core's labels) cannot reach Postgres: the policy test would prove nothing"
probe "$NS_BIZ" "app=intruder" "$dbip" 5432 && bad "an unlisted pod reached Postgres"
# the signing zone (the pods exist: charts.sh installed them)
pod_ip() { kn "$1" get pod "$2" -o jsonpath='{.status.podIP}'; }
a_ip="$(pod_ip "$NS_SIGN" qv-party-a-0)"; b_ip="$(pod_ip "$NS_B" qv-party-b-0)"
gw="app.kubernetes.io/name=qv,app.kubernetes.io/instance=qv-signing-core,app.kubernetes.io/component=gateway"
guard_ip="$(kn "$NS_SIGN" get svc qv-guard-rw -o jsonpath='{.spec.clusterIP}')"
core="app.kubernetes.io/name=qv,app.kubernetes.io/instance=qv-business,app.kubernetes.io/component=core"
probe "$NS_SIGN" "$gw" "$a_ip" 7001 || bad "control: a pod with the gateway's labels cannot reach party A's caller port"
probe "$NS_SIGN" "app=intruder" "$a_ip" 7001 && bad "an unlisted pod in the signing namespace reached party A's caller port"
probe "$NS_SIGN" "app=intruder" "$guard_ip" 5432 && bad "an unlisted pod reached the guard database"
probe "$NS_BIZ" "$core" "$a_ip" 7001 && bad "a business pod reached party A's caller port"
probe "$NS_BIZ" "$core" "$b_ip" 7001 && bad "a business pod reached party B's caller port"
probe "$NS_C" "app.kubernetes.io/name=qv-party" "$a_ip" 7001 && bad "party C reached party A's caller port (only the gateway may)"
probe "$NS_SIGN" "$gw" 1.1.1.1 443 && bad "the gateway reached the internet"
probe "$NS_SIGN" "app.kubernetes.io/name=qv-party" 1.1.1.1 443 && bad "a party reached the internet"
exit $rc
