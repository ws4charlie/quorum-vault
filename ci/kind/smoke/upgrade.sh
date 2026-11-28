#!/usr/bin/env bash
# Case 5: `helm upgrade` with no change is a no-op (no pod is replaced); a change of CONFIGURATION (a value that lands in a ConfigMap) renames that ConfigMap, replaces the pods
# that read it, and core keeps accepting connections during the whole roll (a prober pod connects to the Service twice a second and the case fails on the first refusal).
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"; set +e
cd "$QV_KIND_ROOT"; rc=0; bad() { echo "FAIL: $*"; rc=1; }
chart=deploy/helm/qv-business   # its values: lib.sh biz_values (values-kind.yaml and the lane's overlays, e.g. gate.sh's)
uids() { kn "$NS_BIZ" get pods -l app.kubernetes.io/instance=qv-business -o json | jq -r --arg c "$1" '[.items[] | select(.metadata.labels["app.kubernetes.io/component"]==$c and .metadata.deletionTimestamp==null) | .metadata.uid] | sort | join(",")'; }
cmname() { kn "$NS_BIZ" get deploy qv-business-core -o json | jq -r '.spec.template.spec.containers[0].envFrom[0].configMapRef.name'; }
upg() { hm upgrade qv-business $chart -n "$NS_BIZ" $(biz_values) $(trust_args "$NS_BIZ") "$@" --wait --timeout 5m >/dev/null; }

core0="$(uids core)"; cm0="$(cmname)"
upg || bad "no-change upgrade failed"
[ "$(uids core)" = "$core0" ] && [ "$(cmname)" = "$cm0" ] || bad "a no-change upgrade replaced pods or renamed the ConfigMap"

# the prober: a pod that counts refused connections to core's Service
kn "$NS_BIZ" delete pod kind-prober --ignore-not-found >/dev/null
kn "$NS_BIZ" run kind-prober --image=nginx:1.27-alpine --image-pull-policy=IfNotPresent --restart=Never --labels="qv-kind/prober=true" --command -- sh -c \
  'f=0; n=0; while [ ! -f /tmp/stop ]; do n=$((n+1)); nc -z -w 2 qv-business-core 8443 || { f=$((f+1)); echo "REFUSED $n"; }; sleep 0.5; done; echo "DONE tries=$n refused=$f"' >/dev/null
kn "$NS_BIZ" wait --for=condition=Ready pod/kind-prober --timeout=90s >/dev/null || bad "the prober did not start"

# three rolls in a row, each a new ConfigMap and a new core pod, with the prober running through all of them: one refused connection in any fails the case (core keeps serving for the
# chart's preStop seconds after it is chosen for removal, and a pod leaves only when its replacement is ready)
for n in 1 2 3; do
  prev="$(cmname)"; pods="$(uids core)"
  upg --set oidc.audience=qv-core-smoke$n || bad "changing upgrade $n failed"
  cm1="$(cmname)"
  [ "$cm1" != "$prev" ] || bad "roll $n: a changed ConfigMap value did not rename the ConfigMap ($prev)"
  [ "$(uids core)" != "$pods" ] || bad "roll $n: core's pod was not replaced after its configuration changed"
  kn "$NS_BIZ" get cm "$cm1" -o jsonpath='{.data.QV_OIDC_AUDIENCE}' | grep -qx qv-core-smoke$n || bad "roll $n: the new ConfigMap does not hold the new value"
done
sleep 2
kn "$NS_BIZ" exec kind-prober -- touch /tmp/stop >/dev/null; sleep 1.5
res="$(kn "$NS_BIZ" logs kind-prober | tail -1)"; echo "prober: $res"
case "$res" in "DONE tries="*" refused=0") ;; *) bad "core refused connections during the roll: $(kn "$NS_BIZ" logs kind-prober | grep -c REFUSED) refusals ($res)";; esac
kn "$NS_BIZ" delete pod kind-prober --wait=false >/dev/null
upg || bad "restoring upgrade failed"
exit $rc
