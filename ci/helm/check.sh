#!/usr/bin/env bash
# Chart checks for deploy/helm/qv-business: lint, render both value files, validate against the Kubernetes schemas, then the policy and contract tests.
# Needs helm and kubeconform on PATH (the helm workflow installs pinned versions; locally: brew install helm kubeconform). KUBE_VERSION picks the schema version.
set -euo pipefail
cd "$(dirname "$0")/../.."
chart=deploy/helm/qv-business
KUBE_VERSION="${KUBE_VERSION:-1.31.0}"
out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
for v in values values-kind; do
  dig=""; [ "$v" = values ] && dig="-f ci/helm/ci-digests.yaml"   # production digests are placeholders the chart refuses
  echo "== $v: lint"
  helm lint "$chart" -f "$chart/$v.yaml" $dig --strict
  echo "== $v: template + kubeconform (Kubernetes $KUBE_VERSION)"
  helm template qv "$chart" --namespace qv -f "$chart/$v.yaml" $dig > "$out/$v.yaml"
  kubeconform -strict -summary -kubernetes-version "$KUBE_VERSION" "$out/$v.yaml"
done
echo "== production values with the approval page on: template + kubeconform"
helm template qv "$chart" --namespace qv -f "$chart/values.yaml" -f ci/helm/ci-digests.yaml --set approval.enabled=true > "$out/approval.yaml"
kubeconform -strict -summary -kubernetes-version "$KUBE_VERSION" "$out/approval.yaml"
ci/helm/party-check.sh   # chart list: qv-party (qv-business is above)
ci/helm/certs-check.sh   # deploy/helm/qv-certs (task D5)

echo "== policy and contract tests"
(cd ci/helm && CI=1 go test -count=1 ./...)
