#!/usr/bin/env bash
# Chart checks for deploy/helm/qv-certs: lint and render every cluster in production mode plus the kind values, and validate the output against the
# Kubernetes schemas and the cert-manager CRD schemas. The cert-manager schemas come from datreeio/CRDs-catalog at the commit pinned below (a commit, not a
# branch, so a schema change upstream cannot change this check). The Go checks (certs_test.go) run with the rest of ci/helm.
set -euo pipefail
cd "$(dirname "$0")/../.."
chart=deploy/helm/qv-certs
KUBE_VERSION="${KUBE_VERSION:-1.31.0}"
CRD_COMMIT=784ec895547a36e548e6810b41f27baade3a0890
CRDS="https://raw.githubusercontent.com/datreeio/CRDs-catalog/${CRD_COMMIT}/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"
out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
validate() { kubeconform -strict -summary -kubernetes-version "$KUBE_VERSION" -schema-location default -schema-location "$CRDS" "$1"; }
for c in business signing-core party-b party-c broker; do
  echo "== $c (production values): lint, template, kubeconform"
  helm lint "$chart" -f "$chart/values.yaml" -f ci/helm/certs-ci-values.yaml --set cluster="$c" --strict
  helm template qv-certs "$chart" --namespace qv -f "$chart/values.yaml" -f ci/helm/certs-ci-values.yaml --set cluster="$c" > "$out/$c.yaml"
  validate "$out/$c.yaml"
done
echo "== kind values: lint, template, kubeconform"
helm lint "$chart" -f "$chart/values-kind.yaml" --strict
helm template qv-certs "$chart" --namespace qv -f "$chart/values-kind.yaml" > "$out/kind.yaml"
validate "$out/kind.yaml"
