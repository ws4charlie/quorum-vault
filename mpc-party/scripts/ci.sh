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
go build -o /dev/null ./cmd/qv-attest-broker   # production build: no mock, no test root (TestProductionBrokerHasNoMock)
go test -race -count=1 -timeout 25m ./...
# the verifier tests need the simulated attester, which exists only under -tags teesim
go test -race -count=1 -tags teesim ./internal/attest/...
# the broker tests also need the simulated attester, and a SoftHSM token that the test makes itself (QV_REQUIRE_HSM=1 above: no silent skip)
go test -race -count=1 -tags teesim ./cmd/qv-attest-broker/...
# the attested sealer against the real broker (SoftHSM), the migration, and the crash matrices of DKG and Refresh with attested party processes
go test -race -count=1 -timeout 25m -tags teesim -run 'TestAttested|TestMigration' ./internal/server
go test -race -count=1 -timeout 25m -tags teesim -run 'TestAttested' ./e2e
scripts/restore-drill.sh
