# Load .env if present (dev-only values; see .env.example).
ifneq (,$(wildcard .env))
include .env
export
endif

export CGO_ENABLED := 1
DATABASE_URL ?= postgres://qv@localhost:55432/quorumvault?sslmode=disable
export DATABASE_URL

.PHONY: setup softhsm db-up db-down test test-short build vet run

setup: softhsm db-up

softhsm:
	./scripts/setup-softhsm.sh

db-up:
	docker compose up -d --wait

db-down:
	docker compose down

test:
	QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 go test -count=1 -p 1 ./...

test-short:
	go test -short -p 1 ./...

build:
	go build -o bin/quorumvault ./cmd/quorumvault

vet:
	go vet ./...

run:
	go run ./cmd/quorumvault
