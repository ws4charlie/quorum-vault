# Load .env if present (dev-only values; see .env.example).
ifneq (,$(wildcard .env))
include .env
export
endif

export CGO_ENABLED := 1
DATABASE_URL ?= postgres://qv@localhost:55432/quorumvault?sslmode=disable
export DATABASE_URL

# Local anvil node impersonating Sepolia (docker-compose.yml service "anvil").
LOCAL_RPC_URL := http://127.0.0.1:8545

.PHONY: test-mpc test-mpc-soak test-e2e-evm test-e2e-evm-failure test-e2e-evm-latency test-e2e-evm-flows test-e2e-evm-tx-failures test-e2e-evm-recovery test-demo-v1 mpc-build setup softhsm db-up db-down chain-up chain-down infra-up infra-down test-infra test test-short build vet run demo-local

setup: softhsm db-up chain-up

softhsm:
	./scripts/setup-softhsm.sh

db-up:
	docker compose up -d --wait postgres

db-down:
	docker compose down

chain-up:
	docker compose up -d --wait anvil

chain-down:
	docker compose rm -sf anvil

# Phase 2 infra (profile "infra"): Temporal + its own Postgres + UI, and Redpanda.
infra-up:
	docker compose --profile infra up -d --wait temporal-db temporal temporal-ui redpanda

infra-down:
	docker compose --profile infra rm -sfv temporal-ui temporal temporal-schema temporal-db redpanda

# Smoke test against `make infra-up`: a Temporal workflow and a Redpanda round trip.
test-infra:
	QV_REQUIRE_INFRA=1 go test -count=1 -v ./internal/infratest/... ./internal/workflow/...

test:
	QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 go test -count=1 -p 1 ./...

test-short:
	go test -short -p 1 ./...

# The /v1 demo (HSM-only): broadcast + receipt checks on the local anvil node (make chain-up first).
# Not -short: the full broadcast and receipt checks.
test-demo-v1:
	SEPOLIA_RPC_URL=$(LOCAL_RPC_URL) QV_REQUIRE_CHAIN=1 QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 \
		go test -count=1 -p 1 -timeout 20m -v ./e2e

build:
	go build -o bin/quorumvault ./cmd/quorumvault

vet:
	go vet ./...

run:
	go run ./cmd/quorumvault

# Demo against a server started with SEPOLIA_RPC_URL=$(LOCAL_RPC_URL).
demo-local:
	./scripts/demo-sepolia.sh --local

# Phase 2 / P3a: signing gateway and outbox relay.
.PHONY: build-gateway build-relay test-gateway test-relay

build-gateway:
	go build -o bin/qv-gateway ./cmd/qv-gateway

build-relay:
	go build -o bin/qv-relay ./cmd/qv-relay

# Gateway attack tests and queue tests (needs Postgres and SoftHSM; `make db-up softhsm`).
test-gateway:
	QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 go test -count=1 -p 1 ./internal/gateway/... ./internal/signjob/...

# Relay tests against Redpanda (`make infra-up`).
test-relay:
	QV_REQUIRE_DB=1 QV_REQUIRE_INFRA=1 go test -count=1 -p 1 ./internal/outbox/...

# Phase 2 / P3b: the closed loop (deposit, sweep, withdrawal).
.PHONY: build-core build-worker test-custody
build-core:
	go build -o bin/qv-core ./cmd/qv-core

build-worker:
	go build -o bin/qv-worker ./cmd/qv-worker

# End-to-end closed loop with real everything. Needs: Postgres (`make db-up`), SoftHSM
# (`make softhsm`), Temporal + Redpanda (`make infra-up`) and an anvil node with chain ID
# 11155111 on QV_ANVIL_RPC (default http://127.0.0.1:18545, e.g.
# `docker run -d --rm -p 127.0.0.1:18545:8545 ghcr.io/foundry-rs/foundry:v1.8.5 "anvil --host 0.0.0.0 --chain-id 11155111"`).
test-custody:
	QV_REQUIRE_CUSTODY=1 QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 go test -count=1 -p 1 -timeout 30m -v ./e2e/custody/...

# The end-to-end suite for the EVM chain: the closed loop (deposits, sweeps, withdrawals, hot to cold, refills) with the hot keys on
# two-party MPC (mpc-party A and B, qv-cosigner, real SoftHSM sealing), plus the failure tests. Needs `make mpc-build`, `make softhsm`,
# `make infra-up`, Postgres and anvil. Jobs are named e2e-<chain>-<group>: the chain decides how nonces, UTXOs or blockhashes fail.
# test-e2e-evm runs ALL tests (about 15 minutes). To run one test, or a few, by name (a Go -run regexp):
#   make test-e2e-evm TEST=TestMPCRefreshDuringLiveWithdrawals
#   make test-e2e-evm TEST='TestMPCRefresh|TestHappyPath'
# and, to run only some crash boundaries of TestCrashAtEveryBoundary: QV_CRASH_BOUNDARIES=withdrawal.after_broadcast.
E2E_EVM_ENV := QV_CUSTODY_SIGNER=mpc QV_REQUIRE_CUSTODY=1 QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1
test-e2e-evm:
	$(E2E_EVM_ENV) go test -count=1 -p 1 -timeout 40m -v $(if $(TEST),-run '$(TEST)') ./e2e/custody/...

# The heavy tests, which pull-request CI leaves to the nightly run: every crash boundary, a component killed at each custody
# boundary, the freeze test, and the link tests (kill mid-session, partition).
E2E_EVM_FAILURE := TestCrashAtEveryBoundary|TestColdMoveCrashAtEveryBoundary|TestRebalanceCrashAtEveryBoundary|TestRefillCrashAtEveryBoundary|TestMPCKillSigningComponentAtCustodyBoundary|TestMPCFreezeDuringLiveWithdrawals|TestMPCKillPartyMidSession|TestMPCPartitionBetweenPartiesDuringWithdrawal
test-e2e-evm-failure:
	$(E2E_EVM_ENV) go test -count=1 -p 1 -timeout 40m -v -run '$(E2E_EVM_FAILURE)' ./e2e/custody/...

# The signing latency with delay added between the two parties (20 ms, 100 ms, 1 s per frame): a measurement of a real duration (about
# 2 minutes) that asserts little, so it is not part of test-e2e-evm. The nightly workflow runs it.
test-e2e-evm-latency:
	$(E2E_EVM_ENV) QV_E2E_LATENCY=1 go test -count=1 -p 1 -timeout 20m -v -run 'TestMPCWithdrawalLatencyWithSlowLink' ./e2e/custody/...

# Pull-request CI: everything except the failure tests, in three groups that run in parallel jobs (each on its own runner with its
# own anvil, Temporal, Redpanda and Postgres). Together with test-e2e-evm-failure they cover test-e2e-evm.
#   flows        deposits, sweeps, withdrawals, approvals, hot to cold, refills: the business flows working
#   tx-failures  what the chain does to a transaction: reverted, dropped, stuck, replaced, nonce taken from under us
#   recovery     processes and links dying: gateway and relay restarts, a refresh under load, a worker crash at a boundary
E2E_EVM_FLOWS := TestTwoApproversAndInitiatorCannotApprove|TestApprovalTimeoutVoidsTheHold|TestHumanRejectionVoids|TestInsufficientFundsIsRefused|TestFrozenFactoryDefersSweeps|TestGatewayRejectionReleasesNonceAndHold|TestDuplicateRequestsAndSignals|TestHappyPathETHAndToken|TestWorkflowReplayOfRecordedHistories|TestColdMoveRespectsOpenWithdrawals|TestColdMoveBelowLowRaisesOneAlert|TestRefillCeremonyEndToEnd|TestColdMoveExcessEthAndToken|TestMeasureClosedLoop|TestFiftyCustomersConcurrent|TestRefillImportAndReexportAttacks|TestRefillNotConfirming|TestFactoryAdminRotationCeremony|TestGuardianFreezeAndCeremonyUnfreeze|TestAdminRoleTransferTwoSteps|TestParkedRefillIsClosedByAnOperator|TestRebalanceFeedsADryShardAndWithdrawalsGoThere|TestRebalanceAndToColdDoNotFight|TestRebalanceNeverMovesReservedFunds|TestRebalanceTokenNeedsGasOnSource
E2E_EVM_TX_FAILURES := TestRevertedWithdrawalVoidsAndRecordsFee|TestDroppedTransactionIsReplacedAndPaidOnce|TestConsumedNonceParksWithOneAlert|TestRestartedWorkflowAfterMinedReplacementSettlesOnce|TestStuckTransactionIsReplacedOnce
E2E_EVM_RECOVERY := TestGatewayAndRelayRestart|TestMPCRefreshDuringLiveWithdrawals|TestCrashAtEveryBoundary
test-e2e-evm-flows:
	$(E2E_EVM_ENV) go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_EVM_FLOWS)' ./e2e/custody/...
test-e2e-evm-tx-failures:
	$(E2E_EVM_ENV) go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_EVM_TX_FAILURES)' ./e2e/custody/...
# recovery keeps one crash boundary on pull requests: the worker dies right after the broadcast.
test-e2e-evm-recovery:
	$(E2E_EVM_ENV) QV_CRASH_BOUNDARIES=withdrawal.after_broadcast go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_EVM_RECOVERY)' ./e2e/custody/...

# cb-mpc signing path end to end (needs the C++ build once: `make mpc-build`; Postgres; anvil on 127.0.0.1:18545 with chain
# id 11155111 for the mining test: docker run -d --name qv-anvil-p5b3 -p 127.0.0.1:18545:8545 ghcr.io/foundry-rs/foundry:v1.8.5 "anvil --host 0.0.0.0 --chain-id 11155111").
# Real processes: qv-gateway, mpc-party A and B, qv-cosigner.
mpc-build:
	cd mpc-party && scripts/fetch-build-cbmpc.sh

test-mpc:
	QV_MPC_E2E=1 QV_REQUIRE_DB=1 QV_ANVIL_RPC=http://127.0.0.1:18545 go test -count=1 -p 1 -timeout 20m -v ./e2e/mpcsign/...

# Soak: 50 signatures per second for 10 minutes through the whole path, with RSS and thread counts of every process.
# QV_MPC_SOAK_MINUTES and QV_MPC_SOAK_RATE change the length and the rate.
test-mpc-soak:
	QV_MPC_SOAK=1 QV_MPC_E2E=1 QV_REQUIRE_DB=1 QV_ANVIL_RPC=http://127.0.0.1:18545 go test -count=1 -p 1 -timeout 40m -v -run TestSoakWholePath ./e2e/mpcsign/...
