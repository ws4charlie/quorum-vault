#!/usr/bin/env bash
# Shared by the scripts of the kind lane. Source it; it sets the names that make the cluster this checkout's own.
set -euo pipefail
QV_KIND_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KDIR="$QV_KIND_ROOT/ci/kind"
# shellcheck source=versions.env
. "$KDIR/versions.env"
# One cluster per checkout (PR #104 names the compose projects the same way), so two checkouts and the compose e2e never collide.
QV_KIND_NAME="${QV_KIND_NAME:-qv-kind-$(printf %s "$QV_KIND_ROOT" | shasum | cut -c1-6)}"
CTX="kind-$QV_KIND_NAME"
WORK="$KDIR/.work/$QV_KIND_NAME"            # generated, gitignored: CAs, passwords, values files, test keys. Nothing in it is ever committed.
NS_BIZ=qv; NS_SIGN=qv-signing; NS_B=qv-party-b; NS_C=qv-party-c
ALL_NS="$NS_BIZ $NS_SIGN $NS_B $NS_C"
export KUBECONFIG="${QV_KIND_KUBECONFIG:-$WORK/kubeconfig}"
mkdir -p "$WORK"
k()  { kubectl --context "$CTX" "$@"; }
kn() { local ns="$1"; shift; kubectl --context "$CTX" -n "$ns" "$@"; }
hm() { helm --kube-context "$CTX" "$@"; }
log() { printf '\033[1m== %s\033[0m  (%ss)\n' "$*" "$SECONDS" >&2; }
arch() { case "$(uname -m)" in arm64|aarch64) echo arm64;; *) echo amd64;; esac; }
# The tag of an image, from `repo:tag|digest` lines
pinned_tag() { printf '%s\n' "$PINNED_IMAGES" | awk -F'|' 'NF==2{print $1}'; }
pinned_digest() { printf '%s\n' "$PINNED_IMAGES" | awk -F'|' -v t="$1" '$1==t{print $2}'; }
# Pull by digest, retag, load into the node. Docker's containerd image store cannot `kind load docker-image` a multi-arch image, so ONE archive is made for this
# platform and loaded once (a single save is also much faster than one per image).
pull_pinned() {
  local line tag dig repo
  while IFS='|' read -r tag dig; do
    [ -n "$tag" ] || continue
    repo="${tag%:*}"
    docker image inspect "$tag" >/dev/null 2>&1 || { docker pull -q --platform "linux/$(arch)" "$repo@$dig" >/dev/null; docker tag "$repo@$dig" "$tag"; }
  done <<<"$(printf '%s\n' "$PINNED_IMAGES")"
}
load_images() {
  local tar="$WORK/images.tar"
  docker save --platform "linux/$(arch)" "$@" -o "$tar" 2>/dev/null || docker save "$@" -o "$tar"
  kind load image-archive "$tar" --name "$QV_KIND_NAME" >/dev/null
  rm -f "$tar"
}
