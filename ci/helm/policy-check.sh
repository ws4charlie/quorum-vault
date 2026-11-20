#!/usr/bin/env bash
# Checks for deploy/policy/qv-policy (task D9): lint, render every cluster kind (production, and kind values), validate against the Kubernetes schemas and the
# Kyverno CRD schema (datreeio/CRDs-catalog at a pinned commit), then the offline admission tests (ci/helm/qvpolicy: the rendered policies evaluated against the
# real renders of the application charts and against one denied manifest per rule). Needs helm, kubeconform and go.
set -euo pipefail
cd "$(dirname "$0")/../.."
chart=deploy/policy/qv-policy
KUBE_VERSION="${KUBE_VERSION:-1.31.0}"
CRD_COMMIT=784ec895547a36e548e6810b41f27baade3a0890
CRDS="https://raw.githubusercontent.com/datreeio/CRDs-catalog/${CRD_COMMIT}/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"
out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
common=(--set registry=ghcr.io/ws4charlie/quorum-vault --set 'configWriters.users={system:serviceaccount:flux-system:kustomize-controller}')
for kind in business signing-core party broker; do
  echo "== qv-policy $kind (production): lint, template, kubeconform"
  helm lint "$chart" --strict --set clusterKind="$kind" --set 'namespaces={qv}' "${common[@]}"
  helm template qvp "$chart" --set clusterKind="$kind" --set 'namespaces={qv}' "${common[@]}" > "$out/$kind.yaml"
  kubeconform -strict -summary -kubernetes-version "$KUBE_VERSION" -schema-location default -schema-location "$CRDS" "$out/$kind.yaml"
  echo "== qv-policy $kind (kind values): lint, template, kubeconform"
  helm lint "$chart" --strict -f "$chart/values-kind.yaml" --set clusterKind="$kind" --set 'namespaces={qv}'
  helm template qvp "$chart" -f "$chart/values-kind.yaml" --set clusterKind="$kind" --set 'namespaces={qv}' > "$out/$kind-kind.yaml"
  kubeconform -strict -summary -kubernetes-version "$KUBE_VERSION" -schema-location default -schema-location "$CRDS" "$out/$kind-kind.yaml"
done
echo "== qv-policy: offline admission tests"
(cd ci/helm && go test -count=1 ./qvpolicy)
