#!/usr/bin/env bash
# Makes the CI image of this commit's inputs available (see ci/image-tag.sh for its name, ci/qv-ci.Dockerfile for what is in it).
#
#   ci/ensure-image.sh publish   the `image` job: if the tag is not in the registry, build it and push it (when QV_CI_PUSH=1: same-repository
#                                pull requests and pushes; a fork's token cannot push). Nothing to do when the tag exists.
#   ci/ensure-image.sh use       a job that needs the image: pull it; if it is not there (a fork pull request that changes an input, or a
#                                developer's machine), build it here from the same Dockerfile and keep it local. Never pushes.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="$(ci/image-tag.sh)"
REPO="${IMAGE%:*}"
GO_VERSION="$(ci/image-tag.sh --go-version)"

build() { # build [extra buildx flags]
  docker buildx build --file ci/qv-ci.Dockerfile --build-arg "GO_VERSION=$GO_VERSION" --tag "$IMAGE" "$@" .
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
  echo "usage: $0 publish|use" >&2
  exit 2
  ;;
esac
