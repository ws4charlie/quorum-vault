# Ledger throughput (P1, Postgres)

Feeds P4's decision on whether a Postgres ledger is enough or TigerBeetle is needed.

## Result

Apple M3 Pro, Postgres 16.15 in a container (aarch64, default config: `shared_buffers=128MB`, `synchronous_commit=on`, `max_connections=100`) on 127.0.0.1. 10 s per cell, 1000 funded accounts, all transfers of 1 base unit.

| workload | conns | transfers/s | p50 ms | p99 ms | errors |
|---|---|---|---|---|---|
| uniform | 1 | 565 | 1.64 | 4.26 | 0 |
| uniform | 8 | 2017 | 3.85 | 6.17 | 0 |
| uniform | 32 | 3290 | 9.36 | 16.13 | 0 |
| skewed | 1 | 511 | 2.01 | 2.79 | 0 |
| skewed | 8 | 784 | 11.18 | 16.27 | 0 |
| skewed | 32 | 637 | 54.71 | 136.17 | 0 |

- **uniform**: `from` and `to` drawn uniformly from the 1000 accounts.
- **skewed**: 90% of transfers credit one hot account (`acct-0000`), the rest are uniform.

## Reading it

- Uniform load scales with connections until the commit path saturates: about 3.3k transfers/s at 32 connections.
- A hot account is a serial queue. Every transfer holds the account's row lock until its commit finishes, so throughput is about one commit latency per transfer (roughly 600-800/s here) and extra connections only lengthen the queue: p99 goes from 16 ms to 136 ms while throughput falls.
- So the limit is per hot account, not total. Omnibus hot wallets and clearing accounts (`deposits_pending`, `withdrawals_in_flight`) are the realistic hot accounts. Mitigations that keep Postgres: shard hot accounts (the partition `shard` dimension), or batch several transfers into one transaction.

## Method

`TestMeasure` in `internal/ledger/bench_test.go`, off by default:

```bash
QV_LEDGER_BENCH=1 DATABASE_URL=... go test -count=1 -run TestMeasure -v -timeout 20m ./internal/ledger/
```

- One fresh migrated database per cell; a pool sized to exactly N connections; N worker goroutines in a closed loop (next request starts when the previous returns).
- Each transfer is one real transaction through `Postgres.Transfer`: BEGIN, savepoint, idempotency insert, two ordered row locks, two entries, two balance updates, release, COMMIT. Latency is measured around the whole transaction including commit.
- The zero-sum deferred trigger runs at commit, as in production. `CheckInvariants` passes after every cell.

## Caveats

- Load generator and database share one machine and compete for CPU; loopback has no network latency. Numbers are for comparing designs, not capacity planning (same rule as SoftHSM numbers).
- Container storage on macOS (virtualised fsync) differs from a production NVMe volume. Commit latency dominates here, so absolute numbers will move a lot; the shape (hot account serial, uniform scales) will not.
- Default Postgres config, no tuning, no replication, no `synchronous_commit=off`. Single run per cell, no confidence intervals; p99 over about 5k-30k samples (1-conn cells fewer).
- Transfers only. Hold/Post/Void touch the same rows and cost about the same per operation; not measured separately.
- Savepoint per operation adds a round trip; it is needed so a failed operation leaves no trace in a caller transaction that continues.
