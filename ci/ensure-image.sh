#!/usr/bin/env bash
# Makes the CI image of this commit's inputs available (see ci/image-tag.sh for its name, ci/qv-ci.Dockerfile for what is in it).
#
# The same two commands make the Solana validator image (ci/solana, tag from `ci/image-tag.sh solana`) when a second argument `solana` is given,
# so the validator is built once per change of its Dockerfile and the Solana job pulls it instead of building it (apt-get and a download that
# once ran past the infra wait).
#
#   ci/ensure-image.sh publish [solana]   the `image` job: if the tag is not in the registry, build it and push it (when QV_CI_PUSH=1: same-repository
#                                pull requests and pushes; a fork's token cannot push). Nothing to do when the tag exists.
#   ci/ensure-image.sh use [solana]       a job that needs the image: pull it; if it is not there (a fork pull request that changes an input, or a
#                                developer's machine), build it here from the same Dockerfile and keep it local. Never pushes.
set -euo pipefail
cd "$(dirname "$0")/.."
WHAT="${2:-ci}"
case "$WHAT" in
ci)     IMAGE="$(ci/image-tag.sh)" ;;
solana) IMAGE="$(ci/image-tag.sh solana)" ;;
*)      echo "unknown image $WHAT (ci or solana)" >&2; exit 2 ;;
esac
REPO="${IMAGE%:*}"
GO_VERSION="$(ci/image-tag.sh --go-version)"

# The default builder uses the `docker` driver, which cannot export a registry cache. Build with a docker-container builder (--load still works).
use_container_builder() {
  if docker buildx inspect 2>/dev/null | grep -qi '^Driver:[[:space:]]*docker$'; then
    docker buildx inspect qv-ci >/dev/null 2>&1 || docker buildx create --name qv-ci --driver docker-container >/dev/null
    docker buildx use qv-ci
  fi
}

build() { # build [extra buildx flags]
  use_container_builder
  if [ "$WHAT" = solana ]; then
    docker buildx build --file ci/solana/Dockerfile --tag "$IMAGE" "$@" ci/solana
  else
    docker buildx build --file ci/qv-ci.Dockerfile --build-arg "GO_VERSION=$GO_VERSION" --tag "$IMAGE" "$@" .
  fi
}

case "${1:-use}" in
publish)
  if docker manifest inspect "$IMAGE" >/dev/null 2>&1; then
    echo "$IMAGE already exists: nothing to build"
    exit 0
  fi
  if [ "${QV_CI_PUSH:-}" != "1" ]; then
    echo "$IMAGE does not exist and this run cannot push: the jobs build it themselves"
    exit 0
  fi
  echo "building and pushing $IMAGE"
  build --push --cache-from "type=registry,ref=$REPO:buildcache" --cache-to "type=registry,ref=$REPO:buildcache,mode=max"
  ;;
use)
  if docker pull -q "$IMAGE" >/dev/null 2>&1; then
    echo "pulled $IMAGE"
  else
    echo "$IMAGE is not in the registry: building it here"
    build --load --cache-from "type=registry,ref=$REPO:buildcache"
  fi
  ;;
*)
  echo "usage: $0 publish|use [ci|solana]" >&2
  exit 2
  ;;
esac
