# P0 — Phase 2 foundations

P0 adds the shared ground for the production-shaped custody core: dev infrastructure (Temporal, Redpanda), the whole Phase 2 database schema, and the interfaces later tasks implement. It contains no business logic, except the outbox writer.

## What was built
| Piece | Where |
|---|---|
| Temporal (+ its own Postgres, UI) and Redpanda, profile `infra` | `docker-compose.yml`, `make infra-up` / `infra-down` / `test-infra` |
| Phase 2 schema (ledger, partitions, deposits, withdrawals, sweeps, EVM nonces, sign jobs, approver keys, outbox) | `migrations/0002_custody_core.sql` |
| Partition key | `internal/partition` |
| Ledger interface and errors | `internal/ledger/ledger.go` |
| Chain adapter interface | `internal/chain/adapter.go` |
| Sign-job types | `internal/signjob/signjob.go` |
| Outbox writer | `internal/outbox/outbox.go` |
| Schema tests | `migrations/migrations_test.go` |
| Infra smoke test | `internal/infratest` |

## Temporal: server, worker, database
- **Server** (`temporal`): stores workflow state and hands out tasks. It runs no business code.
- **Worker**: our Go process. It polls a task queue and runs workflow and activity code. Crash it and the server re-delivers the task.
- **Database** (`temporal-db`): the server's only memory. Lose it and every in-flight workflow is gone.

The server image has no schema setup, so a one-shot `temporal-schema` container (admin-tools image) creates the `temporal` and `temporal_visibility` databases first. `temporalio/auto-setup` is deprecated.

## Why two databases
- The business DB holds money facts: ledger, withdrawals, audit. Temporal's DB holds orchestration state, written at a very different rate and shape.
- Separate databases let each be backed up, sized, tuned and failed over on its own. Temporal's retention cleanup never touches ledger rows.
- Neither is the source of truth for the other: the ledger is truth for balances, Temporal only drives steps. Activities must therefore be idempotent.

## Outbox
A service that updates its DB and then publishes to Kafka can crash between the two, losing the event, or publish an event for a change that rolled back. The outbox fixes this: the event is a row in the business transaction (`outbox.Write`). A relay (P3) polls unpublished rows (`published_at IS NULL`), publishes them, then marks them. Delivery is at least once, so consumers dedupe by the row `id`. Kafka is for fan-out only, never for signing tasks.

## Why ledger writes take the caller's transaction
A withdrawal request must create the withdrawal row, put a hold on the customer's balance and write the outbox event. If the ledger opened its own transaction, a crash between them leaves a hold without a withdrawal, or a withdrawal without a hold. Taking the caller's `pgx.Tx` makes all of it commit or roll back as one. The cost: the ledger can never commit on its own, and callers own transaction scope.

## Double entry and zero-sum
Every ledger transaction is a set of entries (account, signed amount) that sum to zero per (chain, asset). Value only moves between accounts; it is never created or destroyed. The database enforces it: a deferred constraint trigger (`ledger_entries_zero_sum`) checks at COMMIT, so a transaction may insert its entries one at a time but cannot commit unbalanced. Entries are append-only (triggers block UPDATE, DELETE, TRUNCATE), so corrections are new reversing entries. A `CHECK` on `ledger_accounts` stops a non-negative account from dropping below zero available (`posted - held >= 0`).

## Gotchas
- `NUMERIC(78,0)` holds any uint256 exactly; Go side uses `*big.Int`.
- Interfaces in `partition`, `ledger.go`, `adapter.go`, `signjob`, `outbox` are frozen: change them only through the lead.
- Tests need `-p 1`: SoftHSM token files are shared.
- `dbtest` gives every test its own migrated database, so migration tests never touch the shared `quorumvault` DB.
- Temporal's `default` namespace does not exist on a fresh server; the smoke test registers it.

## Quiz
1. What does the Temporal server do, and what does a worker do?
2. What is lost if `temporal-db` is wiped? What is not?
3. Give two reasons the business and Temporal databases are separate.
4. What failure does the outbox prevent? What delivery guarantee results, and what must consumers do?
5. Why must `ledger` methods take the caller's `pgx.Tx`?
6. What does "entries sum to zero per (chain, asset)" mean, and why per asset rather than overall?
7. When does the zero-sum check run, and why is it a deferred constraint trigger?
8. How do we correct a wrong ledger entry if entries are append-only?
9. Which constraints keep a customer account from spending held funds?
10. Why is `deposits.dedup_key` unique, and what is its format for EVM?

<details>
<summary>Answers</summary>

1. The server persists workflow state and dispatches tasks; a worker is our process that polls a task queue and runs workflow/activity code.
2. All in-flight workflow state is lost. Ledger balances, withdrawals and audit are not: they live in the business DB.
3. Different write patterns and retention; independent backup, sizing and failover; Temporal cleanup cannot touch money data.
4. A crash between the DB commit and the Kafka publish (lost event), or an event for a rolled-back change. Result: at-least-once delivery, so consumers dedupe by event `id`.
5. So the business row, ledger entries and outbox event commit or roll back together; otherwise a crash leaves holds without withdrawals or the reverse.
6. For each chain+asset the signed amounts add to 0. Summing 10 ETH with -10 USDC to 0 would hide a created ETH and destroyed USDC.
7. At COMMIT, because entries are inserted one row at a time and are only balanced once all are in.
8. Write a new transaction with reversing entries; the old rows stay as history.
9. `CHECK (held >= 0)` and `CHECK (allow_negative OR posted - held >= 0)` on `ledger_accounts`.
10. The same on-chain transfer can be seen twice (rescan, reorg, restart); the unique key makes the second insert fail instead of double-crediting. EVM: `chain:tx_hash:log_index`.
</details>
