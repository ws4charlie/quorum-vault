#!/usr/bin/env bash
# Chart checks for deploy/helm/qv-attest-broker: lint and render the production and the kind (tee-sim) values, validate against the Kubernetes schemas. The policy and
# contract tests (broker_test.go) run with the rest of ci/helm's tests in check.sh. Needs helm and kubeconform; KUBE_VERSION picks the schema version.
set -euo pipefail
cd "$(dirname "$0")/../.."
chart=deploy/helm/qv-attest-broker
KUBE_VERSION="${KUBE_VERSION:-1.31.0}"
out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
for kind in production kind; do
  # production digests are placeholders the chart refuses: the checks use made-up ones; kind's values come last so its SoftHSM settings win over the made-up vendor module
  vals=(-f "$chart/values.yaml" -f ci/helm/ci-broker-values.yaml)
  if [ "$kind" = kind ]; then vals+=(-f "$chart/values-kind.yaml"); else vals+=(-f ci/helm/ci-broker-digests.yaml); fi
  echo "== qv-attest-broker $kind: lint"
  helm lint "$chart" --strict "${vals[@]}"
  echo "== qv-attest-broker $kind: template + kubeconform (Kubernetes $KUBE_VERSION)"
  helm template qv-attest-b "$chart" --namespace qv "${vals[@]}" > "$out/$kind.yaml"
  kubeconform -strict -summary -kubernetes-version "$KUBE_VERSION" "$out/$kind.yaml"
done
