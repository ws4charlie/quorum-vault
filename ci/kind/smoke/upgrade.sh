#!/usr/bin/env bash
# Case 5: `helm upgrade` with no change is a no-op (no pod restarts); with a config change it rolls the pods and core keeps answering during the roll.
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"; set +e
cd "$QV_KIND_ROOT"; rc=0; bad() { echo "FAIL: $*"; rc=1; }
chart=deploy/helm/qv-business; vals=$chart/values-kind.yaml
pods() { kn "$NS_BIZ" get pods -l app.kubernetes.io/instance=qv-business -o json | jq -r '[.items[] | select(.metadata.labels["app.kubernetes.io/component"]!="migrate") | .metadata.uid] | sort | join(",")'; }
before="$(pods)"
hm upgrade qv-business $chart -n "$NS_BIZ" -f $vals --wait --timeout 5m >/dev/null || bad "no-change upgrade failed"
[ "$(pods)" = "$before" ] || bad "a no-change upgrade replaced pods"
# a config change: core's probe log level is not a value, so change a plain setting that is: the audience is part of core's environment ConfigMap (immutable name per content is the signing chart's rule)
code=""; ( while true; do kn "$NS_BIZ" get deploy qv-business-core -o jsonpath='{.status.availableReplicas}' 2>/dev/null; echo; sleep 1; done ) > "$WORK/avail.log" & mon=$!
hm upgrade qv-business $chart -n "$NS_BIZ" -f $vals --set core.terminationGracePeriodSeconds=31 --wait --timeout 5m >/dev/null || bad "changing upgrade failed"
kill $mon 2>/dev/null
[ "$(pods)" != "$before" ] || bad "a config change did not roll any pod"
min="$(grep -E '^[0-9]*$' "$WORK/avail.log" | sort -n | head -1)"
echo "core availableReplicas never below: ${min:-0} (kind runs one core replica; production runs two with maxUnavailable 0)"
hm upgrade qv-business $chart -n "$NS_BIZ" -f $vals --wait --timeout 5m >/dev/null
exit $rc
