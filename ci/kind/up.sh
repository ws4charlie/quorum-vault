#!/usr/bin/env bash
# One command: a kind cluster for this checkout with the dependencies and the four real charts installed and ready.   make kind-up
#   ci/kind/up.sh            everything
#   ci/kind/up.sh cluster    only the cluster, cert-manager and the database operator (phase 1)
# Phases are idempotent: run it again after a failure.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$QV_KIND_ROOT"
PHASE="${1:-all}"

need() { command -v "$1" >/dev/null || { echo "FATAL: $1 is not installed (README: prerequisites)" >&2; exit 1; }; }
for t in docker kind kubectl helm openssl jq; do need "$t"; done
docker info >/dev/null 2>&1 || { echo "FATAL: docker is not running" >&2; exit 1; }

phase_images() {
  log "images: dependencies by digest, services from this checkout"
  pull_pinned
  for t in $LOCAL_IMAGES; do
    docker image inspect "qv-image/$t:local" >/dev/null 2>&1 || { log "building $t"; deploy/images/build.sh "$t"; }
  done
}

phase_cluster() {
  if kind get clusters 2>/dev/null | grep -qx "$QV_KIND_NAME"; then log "cluster $QV_KIND_NAME exists"; else
    log "kind cluster $QV_KIND_NAME"
    sed "s#^    image: .*#    image: $KIND_NODE_IMAGE#" "$KDIR/kind.yaml" > "$WORK/kind.yaml"
    KUBECONFIG="$KUBECONFIG" kind create cluster --name "$QV_KIND_NAME" --config "$WORK/kind.yaml" --wait 180s >&2
  fi
  KUBECONFIG="$KUBECONFIG" kind export kubeconfig --name "$QV_KIND_NAME" >/dev/null
  log "loading images into the node"
  local imgs=() t
  while read -r t; do [ -n "$t" ] && imgs+=("$t"); done <<<"$(pinned_tag)"
  for t in $LOCAL_IMAGES; do imgs+=("qv-image/$t:local"); done
  load_images "${imgs[@]}"
  for n in $ALL_NS; do k create namespace "$n" --dry-run=client -o yaml | k apply -f - >/dev/null; done
  hm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1 || true
  hm repo add cnpg https://cloudnative-pg.github.io/charts >/dev/null 2>&1 || true
  log "cert-manager $CERT_MANAGER_CHART"
  hm upgrade --install cert-manager jetstack/cert-manager --version "$CERT_MANAGER_CHART" -n cert-manager --create-namespace \
    --set crds.enabled=true --set global.leaderElection.namespace=cert-manager --wait --timeout 4m >/dev/null
  log "CloudNativePG operator $CNPG_CHART"
  hm upgrade --install cnpg cnpg/cloudnative-pg --version "$CNPG_CHART" -n cnpg-system --create-namespace --wait --timeout 4m >/dev/null
}

case "$PHASE" in
  images)  phase_images ;;
  cluster) phase_images; phase_cluster ;;
  all)     phase_images; phase_cluster; [ -x "$KDIR/install.sh" ] && "$KDIR/install.sh" ;;
  *) echo "usage: up.sh [all|images|cluster]" >&2; exit 2 ;;
esac
log "done"
