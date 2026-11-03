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

.PHONY: setup softhsm db-up db-down chain-up chain-down infra-up infra-down test-infra test test-short test-e2e build vet run demo-local

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
	QV_REQUIRE_INFRA=1 go test -count=1 -v ./internal/infratest/...

test:
	QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 go test -count=1 -p 1 ./...

test-short:
	go test -short -p 1 ./...

# Broadcast + receipt checks on the local anvil node (make chain-up first).
# Not -short: includes the MPC wallets.
test-e2e:
	SEPOLIA_RPC_URL=$(LOCAL_RPC_URL) QV_REQUIRE_CHAIN=1 QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 \
		go test -count=1 -p 1 -timeout 20m -v ./e2e/...

build:
	go build -o bin/quorumvault ./cmd/quorumvault

vet:
	go vet ./...

run:
	go run ./cmd/quorumvault

# Demo against a server started with SEPOLIA_RPC_URL=$(LOCAL_RPC_URL).
demo-local:
	./scripts/demo-sepolia.sh --local
