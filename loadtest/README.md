# qv-load: the load generator

A Go client that drives the core API the way a customer-facing system does, at arrival rates that do not wait for the system, and judges the run by what the books and the chain say afterwards. Results: [`docs/measurements/load-local.md`](../docs/measurements/load-local.md).

It lives in the root module (`go.mod` is shared): it imports nothing from `internal/`, and the only heavy dependency, go-ethereum for paying deposits on the chain, is already there. A module of its own would add a second place to keep versions in step for no gain.

## Run it

```bash
make setup infra-up softhsm mpc-build         # once per checkout (the e2e stack)
make load-dash-up                              # optional: Prometheus and Grafana for a live run
make load-local SCENARIO=loadtest/scenarios/evm-mixed.json OUT=data/load/mixed-1
```

`make load-local` is `TestLoadLocal` in `e2e/custody/load_test.go`: it starts the stack of this checkout's lane (two-party MPC on SoftHSM, Temporal, Redpanda, Postgres, anvil), starts `qv-load run` against it, samples the processes and the database while it runs, and afterwards checks what only the database can show. Knobs: `SHARDS` (hot shards), `WORKERS`, `CORES` (copies of the stateless services), `DELAY_MS` (delay added to every frame between parties A and B, each way), `RATE_SCALE`, `SEED`, `LABEL`.

Output in `OUT`: `result.json` (the run), `ops.jsonl` (every operation), `stack.json` (what the stack did), `report.html` (the static page; `make load-report OUT=...` makes it again). The test fails when a correctness check fails; timing never fails it.

## Against another target

```bash
go run ./loadtest/cmd/qv-load run -scenario loadtest/scenarios/evm-mixed.json -target target.json -out out/
```

`target.json` (written by whoever sets up the target; this repository holds none): core URLs (round robin), the CA file, how tokens are obtained (`endpoint`: a URL that returns a token for `?actor=NAME`; or `keycloak`: the dev realm's login page, passwords in a secrets directory), the actors (an initiator, an operator, approvers), the approvers' seed files, and the chain (RPC, a funded key, chain ID). See `gen/target.go`. The kind lane and, later, the cloud use this file; the checklist for the cloud run is in the measurement page.

## Scenarios

A scenario (`scenarios/*.json`) has streams of operations (a deposit paid on the chain and followed to credited and swept; a withdrawal followed to confirmed, with the approvals of the tier signed by the named approvers), a ramp, then a hold or a list of steps that multiply every rate, then a drain. `mode` is `open` (Poisson arrivals at the rate, from a fixed seed and the run identifier; an arrival is never delayed by a slow system) or `closed` (a fixed number of users). `objectives` mark the pass lines of a step; the first step that breaks one is the first limit.

| File | What |
|---|---|
| `smoke.json` | a handful of operations; CI and local repeat runs; correctness only |
| `evm-mixed.json` | deposits, small and two-approver withdrawals, a Reconcile every 10 s; rates in steps |
| `evm-withdraw.json`, `evm-deposit.json` | one side each, to find each limit |
| `evm-closed.json` | the mix with a fixed number of users, for comparison |

## What a run checks

Every run ends with: every withdrawal paid exactly once (the destination holds the amount) or not at all; no hold left behind; customers' books equal funded minus paid; deposits credited and every address swept; Reconcile clean; the audit chain verifies; no alert fired (Prometheus, if given); the generator itself kept up. The stack's test adds the database side: no open work, no pending hold, no shared transaction between withdrawals, no failed sign job, Reconcile clean in process, no `ALERT` line in the services' logs, every outbox row published and consumed once.
