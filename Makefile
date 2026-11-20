# Load .env if present (written by `make dev-env`; see .env.example).
ifneq (,$(wildcard .env))
include .env
export
endif

export CGO_ENABLED := 1
# Both Postgres servers want TLS and a client certificate (docs/runbooks/certificates.md): the DSNs name the files `make pki` writes.
# (one variable, QV_PKI_DIR: the environment wins, so a nested make or scripts/e2e-all.sh keeps the directory of its own run)
QV_PKI_DIR ?= $(CURDIR)/data/pki
export QV_PKI_DIR
DATABASE_URL ?= postgres://qv@localhost:55432/quorumvault?sslmode=verify-full&sslrootcert=$(QV_PKI_DIR)/business/admin/ca.crt&sslcert=$(QV_PKI_DIR)/business/admin/tls.crt&sslkey=$(QV_PKI_DIR)/business/admin/tls.key
export DATABASE_URL
# the signing zone's Postgres (the replay-guard databases) is another server with another authority
QV_SIGNING_DB_URL ?= postgres://qv@localhost:55433/qv_signing?sslmode=verify-full&sslrootcert=$(QV_PKI_DIR)/signing/admin/ca.crt&sslcert=$(QV_PKI_DIR)/signing/admin/tls.crt&sslkey=$(QV_PKI_DIR)/signing/admin/tls.key
export QV_SIGNING_DB_URL

.PHONY: migrate pki monitoring-up monitoring-down test-monitoring dev-env test-e2e-all test-mpc test-mpc-soak test-e2e-evm test-e2e-evm-failure test-e2e-evm-latency test-e2e-evm-flows test-e2e-evm-identity test-e2e-approval-web keycloak-up keycloak-down test-e2e-evm-tx-failures test-e2e-evm-recovery mpc-build btc-up btc-down sol-up sol-down test-e2e-sol-deposits test-e2e-sol-signing test-e2e-sol-withdrawals test-e2e-sol-wd-faults test-e2e-sol-sweeps test-e2e-sol-sweep-faults test-e2e-sol-cold test-e2e-sol-cold-crash test-e2e-sol-cold-moves-crash test-e2e-sol-nonces test-e2e-btc-deposits test-e2e-btc-withdrawals test-e2e-btc-recovery test-e2e-btc-sweeps test-e2e-btc-cold test-e2e-btc-refill test-e2e-btc-refill-stuck test-e2e-btc-consolidate test-e2e-btc-batching test-e2e-btc-batching-recovery setup softhsm db-up db-down chain-up chain-down infra-up infra-down test-infra test test-short vet test-e2e-btc-cpfp images

setup: softhsm pki db-up chain-up

# One private CA per trust zone and short-lived certificates for every service, into data/pki (gitignored). Run again to rotate; services reload.
pki:
	./scripts/pki.sh

# Writes .env with random SoftHSM PINs if there is none (never overwrites). Run it first on a fresh checkout.
dev-env:
	./scripts/dev-env.sh

softhsm:
	./scripts/setup-softhsm.sh

# Starts both Postgres servers, then applies the migrations as the OWNER role (qv-core and qv-worker only check them) and lets the service roles log in
# (development only; production enables login itself, see docs/runbooks/database-roles.md).
db-up: pki
	docker compose up -d --wait postgres signing-db
	go run ./cmd/qv-migrate -enable-login
	go run ./cmd/qv-migrate -zone signing -enable-login

# Applies pending migrations as the owner role: run it before starting a new release of qv-core or qv-worker (DATABASE_URL names the admin certificate).
migrate:
	go run ./cmd/qv-migrate

db-down:
	docker compose down

chain-up:
	docker compose up -d --wait anvil

chain-down:
	docker compose rm -sf anvil

# Phase 2 infra (profile "infra"): Temporal + its own Postgres + UI, and Redpanda.
infra-up:
	docker compose --profile infra up -d --wait temporal-db temporal temporal-gate temporal-ui redpanda

infra-down:
	docker compose --profile infra rm -sfv temporal-ui temporal-gate temporal temporal-schema temporal-db redpanda

# Monitoring (profile "monitoring"): a read-only Prometheus over monitoring/ and node-exporter's textfile collector for the gateway's metrics file.
monitoring-up:
	mkdir -p "$${QV_MPC_METRICS_DIR:-.mpc-metrics}"
	docker compose --profile monitoring up -d prometheus node-exporter

monitoring-down:
	docker compose --profile monitoring stop prometheus node-exporter

# promtool check and unit tests of the rules in monitoring/ (pulls the pinned Prometheus image on first use; the Go test skips when promtool is absent).
test-monitoring:
	docker pull "$$(sed -n 's/^ *image: \(prom\/prometheus:.*\)$$/\1/p' docker-compose.yml)"
	go test -count=1 -v ./monitoring/

# Smoke test against `make infra-up`: a Temporal workflow and a Redpanda round trip.
test-infra:
	QV_REQUIRE_INFRA=1 go test -count=1 -v ./internal/infratest/... ./internal/workflow/...

test:
	QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 go test -count=1 -p 1 ./...

test-short:
	go test -short -p 1 ./...

vet:
	go vet ./...

# Phase 2 / P3a: signing gateway and outbox relay.
.PHONY: build-gateway build-relay test-gateway test-relay

build-gateway:
	go build -o bin/qv-gateway ./cmd/qv-gateway
	go build -o bin/qv-route ./cmd/qv-route

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
E2E_EVM_FAILURE := TestCrashAtEveryBoundary|TestColdMoveCrashAtEveryBoundary|TestRebalanceCrashAtEveryBoundary|TestRefillCrashAtEveryBoundary|TestMPCKillSigningComponentAtCustodyBoundary|TestMPCFreezeDuringLiveWithdrawals|TestMPCKillPartyMidSession|TestMPCPartitionBetweenPartiesDuringWithdrawal|TestMPCRouteOneFailedSignatureDoesNotMoveIt
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
E2E_EVM_FLOWS := TestTwoApproversAndInitiatorCannotApprove|TestWebAuthnApprovalThroughTheCoreAPI|TestApprovalTimeoutVoidsTheHold|TestHumanRejectionVoids|TestInsufficientFundsIsRefused|TestFrozenFactoryDefersSweeps|TestGatewayRejectionReleasesNonceAndHold|TestDuplicateRequestsAndSignals|TestHappyPathETHAndToken|TestWorkflowReplayOfRecordedHistories|TestColdMoveRespectsOpenWithdrawals|TestColdMoveBelowLowRaisesOneAlert|TestRefillCeremonyEndToEnd|TestColdMoveExcessEthAndToken|TestMeasureClosedLoop|TestFiftyCustomersConcurrent|TestRefillImportAndReexportAttacks|TestRefillNotConfirming|TestFactoryAdminRotationCeremony|TestGuardianFreezeAndCeremonyUnfreeze|TestAdminRoleTransferTwoSteps|TestParkedRefillIsClosedByAnOperator|TestRebalanceFeedsADryShardAndWithdrawalsGoThere|TestRebalanceAndToColdDoNotFight|TestRebalanceNeverMovesReservedFunds|TestRebalanceTokenNeedsGasOnSource|TestReconcileCleanAtEveryStageOfAWithdrawal|TestReconcileCatchesATokenDifferenceInFlight|TestReconcileCleanAtEveryStageOfARebalance|TestReconcileCleanAtEveryStageOfARefill
E2E_EVM_TX_FAILURES := TestRevertedWithdrawalVoidsAndRecordsFee|TestDroppedTransactionIsReplacedAndPaidOnce|TestConsumedNonceParksWithOneAlert|TestRestartedWorkflowAfterMinedReplacementSettlesOnce|TestStuckTransactionIsReplacedOnce|TestReconcileCleanWhileAWithdrawalIsReplaced|TestReconcileCleanWhileAWithdrawalIsCancelled|TestReconcileCleanWhileAWithdrawalReverts|TestMinedCancelBooksItsGas
E2E_EVM_RECOVERY := TestGatewayAndRelayRestart|TestMPCRefreshDuringLiveWithdrawals|TestMPCOnePartyDownWithdrawalsContinue|TestMPCRestartOfAWhileCIsDown|TestMPCRoutePreferredPairIsSignedAuditedAndHotSwitchable|TestMPCRouteFollowsHealthWithHysteresis|TestCrashAtEveryBoundary|TestReconcileCleanAtEveryStageOfASweep|TestReconcileCleanAtEveryStageOfAColdMove
test-e2e-evm-flows:
	$(E2E_EVM_ENV) go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_EVM_FLOWS)' ./e2e/custody/...
# Real identity provider: a two-approver withdrawal with tokens from the dev Keycloak (docker compose profile identity; `make keycloak-up` first).
test-e2e-evm-identity:
	./scripts/keycloak-env.sh
	$(E2E_EVM_ENV) QV_E2E_KEYCLOAK_URL=$${QV_E2E_KEYCLOAK_URL:-https://127.0.0.1:8180} go test -count=1 -p 1 -timeout 25m -v -run 'TestOIDCWithRealKeycloak' ./e2e/custody/...
# The approval page in a headless Chromium with a virtual passkey (SIMULATED), against the dev Keycloak (`make keycloak-up`) and the real core and gateway.
# Chromium: QV_E2E_CHROME_URL (a running one, as CI has it), QV_E2E_CHROME, or Google Chrome / Chromium on this machine. Signs with the HSM, not mpc-party.
test-e2e-approval-web:
	./scripts/keycloak-env.sh
	QV_REQUIRE_CUSTODY=1 QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 QV_E2E_KEYCLOAK_URL=$${QV_E2E_KEYCLOAK_URL:-https://127.0.0.1:8180} go test -count=1 -p 1 -timeout 25m -v -run 'TestApprovalPageInARealBrowser' ./e2e/custody/...
keycloak-up:
	./scripts/keycloak-env.sh
	docker compose --profile identity up -d --wait keycloak
keycloak-down:
	docker compose --profile identity down keycloak
test-e2e-evm-tx-failures:
	$(E2E_EVM_ENV) go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_EVM_TX_FAILURES)' ./e2e/custody/...
# recovery keeps one crash boundary on pull requests: the worker dies right after the broadcast.
test-e2e-evm-recovery:
	$(E2E_EVM_ENV) QV_CRASH_BOUNDARIES=withdrawal.after_broadcast go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_EVM_RECOVERY)' ./e2e/custody/...

# ---- Bitcoin cell (P7). All Bitcoin e2e runs on real mpc-party: HSM mode has no HD derivation. Jobs are named e2e-btc-<group>.
# Needs `make btc-up infra-up softhsm mpc-build`, Postgres, and bitcoind regtest on QV_BTC_RPC (default http://127.0.0.1:18443).
btc-up:
	docker compose --profile btc up -d --wait bitcoind

btc-down:
	docker compose --profile btc rm -sfv bitcoind

# ---- Solana cell (P8). Deposits run on real mpc-party (2-party HD Ed25519 derivation) and solana-test-validator. Jobs are named e2e-sol-<group>.
# Needs `make sol-up infra-up softhsm mpc-build`, Postgres, and the validator on QV_SOL_RPC (default http://127.0.0.1:18899).
sol-up:
	docker compose --profile solana up -d --build --wait solana

sol-down:
	docker compose --profile solana rm -sfv solana

E2E_SOL_ENV := QV_REQUIRE_SOL=1 QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1
E2E_SOL_DEPOSITS := TestSOL|TestSPL|TestMany|TestRent|TestDerived|TestWrongNetwork|TestReconcile
test-e2e-sol-deposits:
	$(E2E_SOL_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_SOL_DEPOSITS)' ./e2e/sol/...

# Signing zone for Solana (P8-4): qv-gateway, mpc-party A, B and C (2-of-3 Ed25519 hot shard, 2-party HD deposit keys), the cosigners of B and C, Postgres
# and the validator; every signed transaction lands on it. Needs `make sol-up softhsm mpc-build`.
test-e2e-sol-signing:
	$(E2E_SOL_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v ./e2e/solsign/...

# Solana withdrawals on durable nonces (P8-5): the hot shard on 2-of-3 mpc-party, gateway, cosigners, qv-core and qv-worker, the validator. Needs `make sol-up infra-up softhsm mpc-build`.
# Two groups: the flows (settle, fail, refuse, fee raise, park, queue), and the faults (zone attacks, operator pool and cancel, one party down, crash at every boundary).
test-e2e-sol-withdrawals:
	$(E2E_SOL_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run 'TestWdFlows' ./e2e/sol/...

test-e2e-sol-wd-faults:
	$(E2E_SOL_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run 'TestWdFaults|TestWdCrash' ./e2e/sol/...

# Solana sweeps (P8-6): deposit addresses to the hot shard, batched, on durable nonces. Flows (SOL and token, batch, close, stuck, failed), and the faults (zone
# attacks, one party down, crash at every boundary). Needs `make sol-up infra-up softhsm mpc-build`.
test-e2e-sol-sweeps:
	$(E2E_SOL_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run 'TestSwFlows' ./e2e/sol/...

test-e2e-sol-sweep-faults:
	$(E2E_SOL_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run 'TestSwFaults|TestSwCrash' ./e2e/sol/...

# Solana cold tier (P8-7): moves to cold and rebalance between the shards of a pool, the refill ceremony (the cold key is an Ed25519 key in the qv-cold SoftHSM
# token, qv-cold a separate process, only files crossing) with its attacks, a refill that cannot mine and is closed by an operator; and the crash tests at every
# boundary of a refill, a move to cold and a rebalance. Needs `make sol-up infra-up softhsm mpc-build`.
test-e2e-sol-cold:
	$(E2E_SOL_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run 'TestColdMovesAndRebalance|TestColdRefillCeremony|TestColdRefillParked|TestColdRefillRequestExpires|TestColdRefillIsSentAgainUntilItLands|TestColdRefillsOfTwoAssetsRunInParallel' ./e2e/sol/...

test-e2e-sol-cold-crash:
	$(E2E_SOL_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run 'TestColdRefillCrash' ./e2e/sol/...

test-e2e-sol-cold-moves-crash:
	$(E2E_SOL_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run 'TestColdCrash' ./e2e/sol/...

# Retiring and closing nonce accounts to get the rent back: the hot pool through the signing zone, the cold pool in an offline ceremony. Needs `make sol-up infra-up softhsm mpc-build`.
test-e2e-sol-nonces:
	$(E2E_SOL_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run 'TestNonceRetireAndClose|TestColdNonceRetireAndClose' ./e2e/sol/...

E2E_BTC_ENV := QV_REQUIRE_BTC=1 QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1
E2E_BTC_DEPOSITS := TestXpub|TestDeposit|TestTwoOutputs|TestRescan|TestShallowReorg|TestDeepReorg|TestBelowMinimum|TestCoinbase|TestWrongNetwork|TestTwoInputTransactionsSign
E2E_BTC_WITHDRAWALS := TestWithdrawal|TestTwoInputWithdrawal|TestExactAmount|TestManyConcurrent|TestRefusedByTheGateway|TestReorgRemoves
test-e2e-btc-deposits:
	$(E2E_BTC_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_BTC_DEPOSITS)' ./e2e/btc/...

# Withdrawals on real mpc-party: qv-gateway, party B's cosigner, the workflows, bitcoind regtest with -txindex.
test-e2e-btc-withdrawals:
	$(E2E_BTC_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_BTC_WITHDRAWALS)' ./e2e/btc/...

# Sweeps: credited deposits move into the hot shard and become spendable, on real mpc-party (deposit-branch keys), gateway, cosigner and regtest; and the
# recovery of sweeps: bump, cancel, release, an outside spend, every crash boundary.
E2E_BTC_SWEEPS := TestSweep|TestRecoverySweep
test-e2e-btc-sweeps:
	$(E2E_BTC_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_BTC_SWEEPS)' ./e2e/btc/...

# Recovery: fee bumps, cancel, an outside spend, every crash boundary, a killed gateway, a node restarted with an empty mempool. The last one
# restarts the compose bitcoind (`docker compose --profile btc restart bitcoind`), so it needs the node from `make btc-up`.
E2E_BTC_RECOVERY := TestRecovery
test-e2e-btc-recovery:
	$(E2E_BTC_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 30m -v -run '$(E2E_BTC_RECOVERY)' -skip 'TestRecoverySweep' ./e2e/btc/...

# Reconciliation against the chain (scantxoutset) and hot-to-cold moves: bands, rounds under max_inputs, the attacks, crash boundaries, the cancel.
E2E_BTC_COLD := TestCold|TestReconcile
test-e2e-btc-cold:
	$(E2E_BTC_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_BTC_COLD)' ./e2e/btc/...

# Refills on Bitcoin: the cold key in the qv-cold SoftHSM token, qv-cold as a separate process, only files crossing. Needs `make setup` for the token.
E2E_BTC_REFILL_STUCK := TestRefill(Stuck|Offline|Signed|TheLost)
E2E_BTC_REFILL := TestRefill
test-e2e-btc-refill:
	$(E2E_BTC_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_BTC_REFILL)' -skip '$(E2E_BTC_REFILL_STUCK)' ./e2e/btc/...

# Stuck refills: the fee-bumped second ceremony, both ways round, the lost signed file, the fee attacks through real files. Its own group so that each CI job
# stays well under ten minutes (the two together take about six on a laptop).
test-e2e-btc-refill-stuck:
	$(E2E_BTC_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_BTC_REFILL_STUCK)' ./e2e/btc/...

# Consolidation of a hot shard's small outputs: the smallest merged and the largest left free, the conditions that hold it back, one at a time, a withdrawal
# alongside, the cancel, every crash boundary, Reconcile in flight, the attacks through real files.
E2E_BTC_CONSOLIDATE := TestConsolidate
test-e2e-btc-consolidate:
	$(E2E_BTC_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_BTC_CONSOLIDATE)' ./e2e/btc/...

# Batches of withdrawals (several in one transaction), batching on: sealing by count and by age, first in first out, max_in_flight, the prefix under max_inputs, the
# core's second look at every destination, the zone's own ceiling. The second group is the failures: a bumped batch (to the cap, an earlier attempt confirming), the
# cancel of one withdrawal and of a whole batch at each moment, the survivors paid once, a crash at every boundary.
E2E_BTC_BATCHING_RECOVERY := TestBatchRecovery
test-e2e-btc-batching:
	$(E2E_BTC_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run 'TestBatch' -skip '$(E2E_BTC_BATCHING_RECOVERY)' ./e2e/btc/...

test-e2e-btc-batching-recovery:
	$(E2E_BTC_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_BTC_BATCHING_RECOVERY)' ./e2e/btc/...

# CPFP: a send that RBF cannot raise any more is pulled in by a child that spends its change back to the shard: a withdrawal and a batch, the books and
# Reconcile, a cancel after a child, a crash between the child's signature and its broadcast, and every hostile child refused by the real zone.
E2E_BTC_CPFP := TestCPFP
test-e2e-btc-cpfp:
	$(E2E_BTC_ENV) scripts/fail-on-skip.sh go test -count=1 -p 1 -timeout 25m -v -run '$(E2E_BTC_CPFP)' ./e2e/btc/...

# cb-mpc signing path end to end (needs the C++ build once: `make mpc-build`; Postgres; anvil on 127.0.0.1:18545 with chain
# id 11155111 for the mining test: docker run -d --name qv-anvil-p5b3 -p 127.0.0.1:18545:8545 ghcr.io/foundry-rs/foundry:v1.8.5 "anvil --host 0.0.0.0 --chain-id 11155111").
# Real processes: qv-gateway, mpc-party A and B, qv-cosigner.
mpc-build:
	cd mpc-party && scripts/fetch-build-cbmpc.sh

# The audit-head archive (internal/auditchain): the tests start their own SeaweedFS in compliance mode (docker, image pinned in docker-compose.yml);
# the Kafka ones need Redpanda (`make infra-up`; QV_KAFKA_BROKERS if it is not on 19092) and Postgres (`make db-up`).
.PHONY: test-archive
test-archive:
	QV_REQUIRE_DB=1 QV_REQUIRE_INFRA=1 QV_REQUIRE_WORM=1 go test -count=1 -p 1 -timeout 15m -v ./internal/auditchain/...

test-mpc:
	QV_MPC_E2E=1 QV_REQUIRE_DB=1 QV_ANVIL_RPC=$${QV_ANVIL_RPC:-http://127.0.0.1:18545} go test -count=1 -p 1 -timeout 20m -v ./e2e/mpcsign/...

# Soak: 50 signatures per second for 10 minutes through the whole path, with RSS and thread counts of every process.
# QV_MPC_SOAK_MINUTES and QV_MPC_SOAK_RATE change the length and the rate.
test-mpc-soak:
	QV_MPC_SOAK=1 QV_MPC_E2E=1 QV_REQUIRE_DB=1 QV_ANVIL_RPC=$${QV_ANVIL_RPC:-http://127.0.0.1:18545} go test -count=1 -p 1 -timeout 40m -v -run TestSoakWholePath ./e2e/mpcsign/...

# Every CI test group at the same time, each lane with its own Postgres, anvil, bitcoind and SoftHSM tokens (scripts/e2e-all.sh; needs `make softhsm mpc-build`).
#   make test-e2e-all                        all groups
#   make test-e2e-all GROUPS=e2e-btc-cold,test   some groups (CI job names; evm and btc stand for all of theirs)
#   make test-e2e-all LANES=4                another number of lanes
test-e2e-all:
	QV_E2E_GROUPS='$(GROUPS)' $(if $(LANES),LANES=$(LANES)) scripts/e2e-all.sh

# Container images of every deployable and the tools images (deploy/images/README.md): production images and the -dev variants, built locally, never pushed.
# The first build compiles cb-mpc and takes several minutes. `deploy/images/build.sh repro` builds every binary twice and compares the hashes.
images:
	deploy/images/build.sh

# Business-zone chart checks (deploy/helm/qv-business): lint, render, Kubernetes schemas, policy and image-contract tests. Needs helm and kubeconform (brew install helm kubeconform).
helm-check:
	ci/helm/check.sh
