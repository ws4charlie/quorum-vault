#!/usr/bin/env bash
# The image pins of the kind lane, checked without a cluster or a network (run by .github/workflows/helm.yml; also by hand):
#   1. versions.env: every PINNED_IMAGES line is `repo:tag|sha256:<64 hex>` with an exact tag (not latest), KIND_NODE_IMAGE carries a digest, and the
#      cert-manager images carry the chart's version (the chart pulls its images by that tag; up.sh loads the pinned ones under it).
#   2. every image the lane's manifests, scripts and values-kind files name is a pinned tag, or qv-image/<name>:local built by the lane
#      (LOCAL_IMAGES, or a literal deploy/images/build.sh argument in ci/kind), or one of the EXEMPT names below.
# Fails listing every offender.
#   ci/kind/check-pins.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=versions.env
. ci/kind/versions.env
# Names that are not pulled, each with the reason. Nothing else may be unpinned.
EXEMPT="
docker.io/library/busybox:1      smoke/admission.sh: a pod the admission policy must REFUSE (image from another registry); it is never created
qv-image/pause:local             smoke/admission.sh: the node's own pause image (part of the pinned node image), retagged inside the node
qv-image/qv-approval-web:local   qv-business values-kind: approval.enabled is false in kind, so no pod uses it
"
fail=0
bad() { echo "UNPINNED: $*"; fail=1; }

# 1. versions.env
pinned=" "
while IFS= read -r line; do
  [ -n "$line" ] || continue
  if [[ ! "$line" =~ ^([a-z0-9./_-]+):([A-Za-z0-9._-]+)\|sha256:[0-9a-f]{64}$ ]]; then bad "versions.env: '$line' is not repo:tag|sha256:<64 hex>"; continue; fi
  tag="${BASH_REMATCH[2]}"; ref="${line%%|*}"
  [ "$tag" != latest ] || bad "versions.env: $ref: latest is not an exact tag"
  case "$ref" in quay.io/jetstack/cert-manager-*) [ "$tag" = "$CERT_MANAGER_CHART" ] || bad "versions.env: $ref, but CERT_MANAGER_CHART is $CERT_MANAGER_CHART (the chart pulls its own version's tag)";; esac
  pinned+="$ref "
done <<<"$PINNED_IMAGES"
[[ "$KIND_NODE_IMAGE" =~ ^[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$ ]] || bad "versions.env: KIND_NODE_IMAGE=$KIND_NODE_IMAGE has no digest"

# 2. what the lane names
built=" $LOCAL_IMAGES "
while IFS= read -r args; do for n in $args; do case "$n" in *'$'*|-*) ;; *) built+="$n ";; esac; done; done < <(
  git grep -h -o 'deploy/images/build\.sh[^;&|>]*' -- ci/kind | sed 's#deploy/images/build\.sh##')
refs="$(
  {
    # image: / imageName: in manifests and heredocs, --image=, and *IMG= / img= assignments in scripts; comment lines are skipped
    git grep -h -E 'image|IMG|img' -- 'ci/kind/*.yaml' 'ci/kind/*.sh' | perl -ne '
      next if /^\s*#/;
      print "$1\n" while /(?:\bimage|\bimageName):\s*"?([^\s"\x27|#]+)/g;
      print "$1\n" while /--image=([^\s"\x27]+)/g;
      print "$1\n" while /(?:IMG|\bimg)="?([^\s";\x27]+)/g;'
    # values-kind: `{ ..., tag: T, repository: R }` on one line
    git grep -h -E 'repository:' -- 'deploy/helm/*/values-kind*.yaml' | sed -n -E 's/.*tag:[[:space:]]*"?([^,"[:space:]}]+)"?.*repository:[[:space:]]*"?([^,"[:space:]}]+).*/\2:\1/p'
  } | grep -E '^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]{64})?$' | sort -u
)"
[ -n "$refs" ] || { echo "check-pins: found no image reference at all: the extraction is broken"; exit 1; }
n=0
while IFS= read -r ref; do
  n=$((n + 1))
  case "$pinned" in *" $ref "*) continue;; esac
  if [[ "$ref" =~ ^qv-image/([a-z0-9-]+):local$ ]]; then case "$built" in *" ${BASH_REMATCH[1]} "*) continue;; esac; fi
  [[ "$ref" == "${KIND_NODE_IMAGE}" ]] && continue
  awk -v r="$ref" '$1==r{f=1} END{exit !f}' <<<"$EXEMPT" && continue
  where="$(git grep -l -F -- "$ref" -- ci/kind 'deploy/helm/*/values-kind*.yaml' || git grep -l -F -- "${ref%:*}" -- 'deploy/helm/*/values-kind*.yaml' || true)"
  bad "$ref is named by the kind lane ($(printf '%s' "$where" | tr '\n' ' ')) but is not in PINNED_IMAGES of ci/kind/versions.env (repo:tag|digest), not a lane-built qv-image/<name>:local, and not exempt"
done <<<"$refs"
[ "$fail" = 0 ] && echo "check-pins: ok ($n image references, all pinned, built by the lane or exempt)"
exit "$fail"
