# Closed-loop measurements (P3b)

Local run, all components real and in separate processes: Postgres 16 (Docker), Temporal 1.32 and Redpanda (Docker), anvil v1.8.5 (chain ID 11155111, automine: a block per transaction, instant), SoftHSM signing in `qv-gateway`, `qv-worker`, `qv-relay`, `qv-core`. Machine: Apple Silicon laptop. Confirmations set to 0. These are latencies of the system's own steps on a chain with no block time; they say nothing about a real network (add block time and confirmations) and nothing about capacity (SoftHSM is never used for capacity planning).

Reproduce: `make test-custody` runs everything; the figures below come from

```
QV_REQUIRE_CUSTODY=1 QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 go test -count=1 -p 1 -v -run TestMeasureClosedLoop ./e2e/custody
```

## One withdrawal, step by step

15 sequential withdrawals after a warm-up one (status polled every 5 ms from the `withdrawals` row; times are from the API call). Lowest tier, so the worker's automated key approves.

| Step (status reached) | Median | p95 | What happens |
|---|---:|---:|---|
| `requested` | 8 ms | 11 ms | API: row, hold, outbox event in one transaction |
| `approved` | 37 ms | 50 ms | Temporal starts the workflow; automated approval; reserve hot liquidity |
| `signing` | 60 ms | 74 ms | Build the transaction, allocate the nonce, enqueue the sign job (one transaction) |
| `broadcast` | 398 ms | 411 ms | Gateway claims the job (polls every 200 ms), checks it, signs in SoftHSM; the workflow notices (polls every 300 ms), assembles and sends |
| `confirmed` | 421 ms | 436 ms | Transaction final; ledger settled (post hold, payout, fee), outbox event |

**End to end: median 421 ms, p95 436 ms, max 439 ms** (15 runs). About 340 ms of it is the signing step; the two polling intervals (gateway 200 ms, job wait 300 ms) account for most of that, not the signature itself. Lower intervals would cut it; they are set for a quiet database.

The first withdrawal after start is slower (cold connections, first HSM session): 429 ms in this run, so the warm-up effect is small.

## Other steps

| Step | Time |
|---|---:|
| Deposit sent -> credited to the customer (scan every 500 ms) | 210 ms |
| Deposit sent -> sweep confirmed (planner every 1 s, one sweep, deploys the forwarder) | 1.58 s |
| 20 withdrawals started at once -> all confirmed (one hot address, so one nonce counter) | 1.38 s (14.5 /s) |

The 20-at-once figure is bounded by serial nonces on one hot address and by the gateway's poll; sharding the hot wallet across addresses is the intended way to raise it (P4 measures that).

## The 50-customer run

`TestFiftyCustomersConcurrent`: 50 customers, ETH and token deposits (one dust deposit, one below `min_deposit`), two hot shards, 49 withdrawals started 10 at a time. **About 20 s in total** on this machine. Afterwards `Reconcile` is clean and 566 outbox events were all published and consumed once after de-duplication.

Findings from this run:
- The first version of the planner asked the node about all candidates in one activity and hit the 20-second activity timeout; it now plans in passes of at most 25 with a 2-minute timeout.
- The first version also let every candidate sweep run at once (about 80 workflows). Every sweep takes row locks on the same few ledger accounts (`dep`, `sweep`, `hot`, `fee`) and a nonce on the one sweep destination, so they queued behind each other and the run took 2 to 3 minutes, sometimes more than the test's 3-minute wait. The planner now keeps at most 12 sweeps open; the same run takes about 20 s. More parallelism than that only adds lock waits.
