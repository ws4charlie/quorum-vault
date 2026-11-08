#!/usr/bin/env bash
# Prints the name of the CI image for the inputs at this commit: ghcr.io/ws4charlie/qv-ci:<hash of every input>.
# The inputs: the Dockerfile and its ignore file, the two scripts it runs, the cb-mpc pin, and the Go version: the highest `go` line of the
# repository's go.mod files (mpc-party/go.mod asks for a newer Go than the root module, and builds with GOTOOLCHAIN=local). Anything else
# (the tests, the Go code) is not in the image, so changing it never changes the tag. `ci/image-tag.sh --go-version` prints the Go version.
set -euo pipefail
cd "$(dirname "$0")/.."
GO_VERSION="$(for f in go.mod mpc-party/go.mod mpc-party/api/go.mod; do awk '$1=="go"{print $2; exit}' "$f"; done | sort -V | tail -1)"
if [ "${1:-}" = "--go-version" ]; then echo "$GO_VERSION"; exit 0; fi
sum() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }
HASH="$( { for f in ci/qv-ci.Dockerfile ci/qv-ci.Dockerfile.dockerignore mpc-party/scripts/install-toolchain-linux.sh mpc-party/scripts/fetch-build-cbmpc.sh mpc-party/cbmpc.pin; do
             printf '%s\n' "$f"; cat "$f"; done; printf 'go %s\n' "$GO_VERSION"; } | sum | cut -c1-16)"
echo "${QV_CI_REGISTRY:-ghcr.io/ws4charlie}/qv-ci:${HASH}"
