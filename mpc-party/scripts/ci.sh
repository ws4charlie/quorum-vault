#!/usr/bin/env bash
# The exact commands of the `mpc-party` CI job (minus checkout/setup-go/cache), so they can be reproduced in a container:
#   docker run --platform linux/amd64 -v "$PWD":/src ubuntu:24.04 bash /src/mpc-party/scripts/ci.sh   (Go on PATH required)
set -euo pipefail
cd "$(dirname "$0")/.."
export CGO_ENABLED=1 CC=clang-20 CXX=clang++-20
scripts/install-toolchain-linux.sh
# SoftHSM tokens qv-party-1/2 for the sealer tests and the restore drill (needs the repository's scripts/ next to mpc-party/)
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
if ! command -v softhsm2-util >/dev/null; then $SUDO apt-get install -y -qq softhsm2 >/dev/null; fi
../scripts/setup-softhsm.sh >/dev/null
export QV_REQUIRE_HSM=1
scripts/fetch-build-cbmpc.sh
(cd api && go vet ./... && go build ./... && go test -count=1 ./...)
go vet ./...
go build -o /dev/null ./cmd/mpc-party
go test -race -count=1 -timeout 25m ./...
scripts/restore-drill.sh
