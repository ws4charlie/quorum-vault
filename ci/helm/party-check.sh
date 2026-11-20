#!/usr/bin/env bash
# Chart checks for deploy/helm/qv-party: lint and render every role for the production and the kind values, validate against the Kubernetes schemas. The policy and
# contract tests (party_test.go) run with the rest of ci/helm's tests in check.sh. Needs helm and kubeconform; KUBE_VERSION picks the schema version.
set -euo pipefail
cd "$(dirname "$0")/../.."
chart=deploy/helm/qv-party
KUBE_VERSION="${KUBE_VERSION:-1.31.0}"
out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
for kind in production kind; do
  for role in A B C; do
    # production digests are placeholders the chart refuses: the checks use made-up ones; kind's values come last so its SoftHSM settings win over the made-up vendor module
    vals=(-f "$chart/values.yaml" -f ci/helm/ci-party-values.yaml)
    if [ "$kind" = kind ]; then vals+=(-f "$chart/values-kind.yaml"); else vals+=(-f ci/helm/ci-party-digests.yaml); fi
    rel="qv-party-$(echo "$role" | tr 'A-Z' 'a-z')"
    echo "== qv-party $kind role $role: lint"
    helm lint "$chart" --strict --set "role=$role" "${vals[@]}"
    echo "== qv-party $kind role $role: template + kubeconform (Kubernetes $KUBE_VERSION)"
    helm template "$rel" "$chart" --namespace qv --set "role=$role" "${vals[@]}" > "$out/$kind-$role.yaml"
    kubeconform -strict -summary -kubernetes-version "$KUBE_VERSION" "$out/$kind-$role.yaml"
  done
done
