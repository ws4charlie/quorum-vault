#!/usr/bin/env bash
# Chart checks for deploy/helm/qv-monitoring and the metrics parts of the other charts (task D10): lint and render each cluster kind, validate against the Kubernetes schemas and
# the Prometheus Operator CRD schemas (datreeio/CRDs-catalog at a pinned commit), and render the business chart with metrics on and the signing charts with the agent on.
# The Go checks (monitoring_test.go) run with the rest of ci/helm in check.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."
chart=deploy/helm/qv-monitoring
KUBE_VERSION="${KUBE_VERSION:-1.31.0}"
CRD_COMMIT=784ec895547a36e548e6810b41f27baade3a0890
CRDS="https://raw.githubusercontent.com/datreeio/CRDs-catalog/${CRD_COMMIT}/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"
out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
validate() { kubeconform -strict -summary -kubernetes-version "$KUBE_VERSION" -schema-location default -schema-location "$CRDS" "$1"; }
for k in central business signing; do
  echo "== qv-monitoring $k: lint, template, kubeconform"
  helm lint "$chart" --strict --set clusterKind="$k" --set alertmanager.enabled=true
  helm template qv-monitoring "$chart" --namespace monitoring --set clusterKind="$k" --set alertmanager.enabled=true > "$out/$k.yaml"
  if [ -s "$out/$k.yaml" ]; then validate "$out/$k.yaml"; else echo "(renders nothing)"; fi
done
echo "== qv-business with metrics on: template, kubeconform"
helm template qv deploy/helm/qv-business --namespace qv -f deploy/helm/qv-business/values.yaml -f ci/helm/ci-digests.yaml --set metrics.enabled=true > "$out/business-metrics.yaml"
validate "$out/business-metrics.yaml"
echo "== qv-signing-core and qv-party with the agent on: template, kubeconform"
helm template qv deploy/helm/qv-signing-core --namespace qv -f ci/helm/signing-core-ci.yaml --set metrics.agent.enabled=true --set metrics.agent.remoteWrite.url=https://metrics.example.invalid/api/v1/write --set metrics.agent.remoteWrite.tlsSecret=qv-remote-write-tls --set metrics.agent.cluster=signing-core > "$out/sc-agent.yaml"
validate "$out/sc-agent.yaml"
for role in A B C; do
  helm template "qv-party-$(echo $role | tr A-Z a-z)" deploy/helm/qv-party --namespace qv --set role=$role -f ci/helm/ci-party-values.yaml -f ci/helm/ci-party-digests.yaml --set metrics.agent.enabled=true --set metrics.agent.remoteWrite.url=https://metrics.example.invalid/api/v1/write --set metrics.agent.remoteWrite.tlsSecret=qv-remote-write-tls --set metrics.agent.cluster="party-$(echo $role | tr A-Z a-z)" --set 'network.metricsRemoteWrite.to[0].ipBlock.cidr=10.9.0.0/28' > "$out/party-$role-agent.yaml"
  validate "$out/party-$role-agent.yaml"
done
