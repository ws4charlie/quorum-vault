#!/usr/bin/env bash
# The image pins of the kind lane, checked without a cluster or a network (run by .github/workflows/helm.yml; also by hand):
#   1. versions.env: every PINNED_IMAGES line is `repo:tag|sha256:<64 hex>` with an exact tag (not latest), KIND_NODE_IMAGE carries a digest, and the
#      cert-manager images carry the chart's version (the chart pulls its images by that tag; up.sh loads the pinned ones under it).
#   2. every image the lane's manifests, scripts and values-kind files name is a pinned tag, or qv-image/<name>:local built by the lane
#      (LOCAL_IMAGES, or a literal deploy/images/build.sh argument in ci/kind), or one of the EXEMPT names below. Scripts: image:, imageName:,
#      --image=X / --image X, *IMG= / img=, and the image of `docker run` / `dk` (teesim.sh's docker-run helper). values-kind files are parsed as YAML
#      (ci/helm/kindimages, Go: the helm workflow has Go for ci/helm), so key order and block or flow style do not matter.
#   3. every PINNED_IMAGES entry is used by some lane file (an unused pin is a stale line).
# Fails listing every offender. Needs git, perl and Go.
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
      print "$1\n" while /--image[= ]+"?([^\s"\x27]+)/g;
      if (/(?:\bdocker\s+run|(?:^|[\s;&|(])dk)\s+(.*)/) {    # docker run [flags] IMAGE ...: the first word that is not a flag or a flag value
        (my $rest = $1) =~ s/\$\([^)]*\)/X/g; my @w = map { s/^["\x27]|["\x27]$//gr } split /\s+/, $rest;
        my %val = map { $_ => 1 } qw(-v --volume -e --env -w --workdir -u --user --entrypoint --name --network --platform -p --publish --mount -l --label --cap-add --cap-drop --security-opt --add-host --env-file --pull);
        while (@w) { my $x = shift @w; if ($x =~ /^-/) { shift @w if $val{$x}; next } print "$x\n"; last }
      }
      print "$1\n" while /(?:IMG|\bimg)="?([^\s";\x27]+)/g;'
    # values-kind: every map with a repository key, parsed as YAML
    git ls-files -z -- 'deploy/helm/*/values-kind*.yaml' | xargs -0 -I{} printf '%s\n' "$PWD/{}" | xargs go -C ci/helm run ./kindimages
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
# 3. no stale pin: each pinned tag is named somewhere in the lane (manifests, scripts, values-kind)
for ref in $pinned; do
  case "$ref" in quay.io/jetstack/cert-manager-*|ghcr.io/cloudnative-pg/cloudnative-pg:*) continue;; esac   # pulled by the cert-manager and CNPG charts (up.sh), named by no lane file
  printf '%s\n' "$refs" | grep -qxF -- "$ref" || bad "versions.env: $ref is pinned but no kind lane file names it (a stale pin: drop the line)"
done
[ "$fail" = 0 ] && echo "check-pins: ok ($n image references, all pinned, built by the lane or exempt)"
exit "$fail"
