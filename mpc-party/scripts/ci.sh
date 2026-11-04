#!/usr/bin/env bash
# The exact commands of the `mpc-party` CI job (minus checkout/setup-go/cache), so they can be reproduced in a container:
#   docker run --platform linux/amd64 -v "$PWD":/src ubuntu:24.04 bash /src/mpc-party/scripts/ci.sh   (Go on PATH required)
set -euo pipefail
cd "$(dirname "$0")/.."
export CGO_ENABLED=1 CC=clang-20 CXX=clang++-20
scripts/install-toolchain-linux.sh
scripts/fetch-build-cbmpc.sh
go vet ./...
go test -race -count=1 ./...
