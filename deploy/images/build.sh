#!/usr/bin/env bash
# Builds the images of deploy/images/Dockerfile into the local Docker. Nothing is pushed or signed.
#
#   deploy/images/build.sh               every production image and the -dev variants (what `make images` runs)
#   deploy/images/build.sh qv-core ...   only these targets
#   QV_CHECK_SET=release deploy/images/build.sh   only the production images (the publish job)
#   deploy/images/build.sh repro         builds every binary twice from scratch and compares their SHA-256 (the reproducibility check)
#
# Images are named ${QV_IMAGE_PREFIX:-qv-image/}<target>:${QV_IMAGE_TAG:-local}. SOURCE_DATE_EPOCH defaults to the commit time of HEAD: it fixes
# the file times in the layers and the image's creation time (BuildKit rewrite-timestamp), so two builds of one commit can give one image digest.
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=images.sh
. deploy/images/images.sh
: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
export SOURCE_DATE_EPOCH
GO_VERSION="$(for f in go.mod mpc-party/go.mod mpc-party/api/go.mod; do awk '$1=="go"{print $2; exit}' "$f"; done | sort -V | tail -1)"
grep -q "ARG GO_VERSION=$GO_VERSION\$" deploy/images/Dockerfile || { echo "FATAL: deploy/images/Dockerfile pins another Go than the go.mod files ask for ($GO_VERSION): update GO_VERSION and both SHA-256 values" >&2; exit 1; }
COMMON=(--file deploy/images/Dockerfile --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" --provenance=false --sbom=false)

if [ "${1:-}" = repro ]; then
  out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
  for n in 1 2; do
    # --no-cache: every layer is rebuilt. The Go module download cache (a cache mount) is only a download cache; go.sum decides the bytes.
    docker buildx build "${COMMON[@]}" --no-cache --target bins --output "type=local,dest=$out/$n" . >&2
  done
  (cd "$out/1" && sha256sum * | sort -k2) >"$out/h1"; (cd "$out/2" && sha256sum * | sort -k2) >"$out/h2"
  cat "$out/h1"
  if cmp -s "$out/h1" "$out/h2"; then echo "REPRODUCIBLE: two builds, $(wc -l <"$out/h1" | tr -d ' ') binaries, identical SHA-256"; else echo "NOT REPRODUCIBLE:"; diff "$out/h1" "$out/h2"; exit 1; fi
  # The measurement an allowlist entry is made from (SIMULATED enclave: SHA-384 over the party binary and a fixed measured configuration) must be equal across
  # the two builders. Checked on the binaries themselves, so it is also checked when the file hashes differ for a reason that would be hidden by the image.
  python3 deploy/images/measure-release.py selftest
  printf '{"role":"A","note":"fixed configuration of the reproducibility check"}' >"$out/measured-config.json"
  python3 deploy/images/measure-release.py same --binary "$out/1/mpc-party" --binary "$out/2/mpc-party" --config "$out/measured-config.json"
  exit 0
fi

if [ $# -gt 0 ]; then targets=("$@"); elif [ "${QV_CHECK_SET:-}" = release ]; then targets=($(qv_release_images | cut -d: -f1))   # the publish job: production images only
else targets=($(qv_all_images | cut -d: -f1)); fi
for t in "${targets[@]}"; do
  echo "== $t" >&2
  docker buildx build "${COMMON[@]}" --target "$t" \
    --label "org.opencontainers.image.source=https://github.com/ws4charlie/quorum-vault" \
    --label "org.opencontainers.image.licenses=NOASSERTION" \
    --output "type=docker,name=${QV_IMAGE_PREFIX}${t}:${QV_IMAGE_TAG},rewrite-timestamp=true" .
done
