#!/usr/bin/env bash
# The cluster policy chart (deploy/policy/qv-policy) in kind mode, as a cluster's own operators would install it: one release, before the workloads. It labels ONE namespace of its own
# (qv-ptest) and no namespace of the lane: the lane's own port-forwards into the signing namespaces are exactly what the exec rule refuses outside the break-glass group, and the lane is
# not a break-glass user. The admission case (smoke/admission.sh) tests the rules in qv-ptest. Idempotent.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$QV_KIND_ROOT"
log "qv-policy (kind mode) for the namespace $NS_PTEST"
hm upgrade --install qv-policy deploy/policy/qv-policy -n kube-system -f deploy/policy/qv-policy/values-kind.yaml \
  --set clusterKind=signing-core --set "namespaces={$NS_PTEST}" --wait --timeout 2m > /dev/null
