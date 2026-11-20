#!/usr/bin/env bash
# Chart checks for deploy/helm/qv-signing-core: lint, render production and kind values, validate against the Kubernetes schemas. The policy and contract tests run in
# the Go tests (signing_core_test.go) that check.sh starts. ci/helm/signing-core-ci.yaml holds the made-up digests and the values every release must set.
set -euo pipefail
cd "$(dirname "$0")/../.."
chart=deploy/helm/qv-signing-core
KUBE_VERSION="${KUBE_VERSION:-1.31.0}"
out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
for v in values values-kind; do
  files=(-f ci/helm/signing-core-ci.yaml); [ "$v" = values-kind ] && files+=(-f "$chart/values-kind.yaml")
  echo "== qv-signing-core $v: lint"
  helm lint "$chart" "${files[@]}" --strict
  echo "== qv-signing-core $v: template + kubeconform (Kubernetes $KUBE_VERSION)"
  helm template qv "$chart" --namespace qvs "${files[@]}" > "$out/$v.yaml"
  kubeconform -strict -summary -kubernetes-version "$KUBE_VERSION" "$out/$v.yaml"
done
