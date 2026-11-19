#!/usr/bin/env bash
# Pushes every image to $REGISTRY with the tag $TAG, with an SBOM and build provenance attached, and signs each pushed digest with cosign (keyless).
# ONLY the manual `publish` job of .github/workflows/images.yml runs this, and only when a maintainer sets its input to true. Nobody runs it by hand
# from a laptop, and no pull request reaches it. It needs `docker login` to the registry and, for signing, an OIDC token (id-token: write).
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${REGISTRY:?REGISTRY, e.g. ghcr.io/<owner>}"; : "${TAG:?TAG, e.g. the commit sha}"
# shellcheck source=images.sh
. deploy/images/images.sh
: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct)}"; export SOURCE_DATE_EPOCH
while IFS=: read -r name _ _; do
  ref="$REGISTRY/$name:$TAG"
  docker buildx build --file deploy/images/Dockerfile --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" --target "$name" \
    --sbom=true --provenance=mode=max --metadata-file "$RUNNER_TEMP/$name.json" \
    --output "type=image,name=$ref,push=true,rewrite-timestamp=true" .
  digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$RUNNER_TEMP/$name.json")"
  cosign sign --yes "$REGISTRY/$name@$digest"
  echo "$REGISTRY/$name@$digest"
done < <(qv_all_images)
