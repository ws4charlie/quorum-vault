# Two-party MPC signer in the closed loop (P5b-5)

Local run, all components real and in separate processes: `mpc-party` A and B (production build, cb-mpc v0.2.2, share sealing in
SoftHSM tokens `qv-party-1` / `qv-party-2`), `qv-cosigner`, `qv-gateway`, `qv-worker`, `qv-core`, `qv-relay`, Postgres 16,
Temporal, Redpanda, anvil (chain ID 11155111, instant blocks). Machine: Apple Silicon laptop, everything on one host over
loopback. These figures say nothing about a real network or capacity planning; they show how the signer behaves.

Reproduce: `make test-e2e-evm` (all tests), `make test-mpc-soak` (soak), `QV_REQUIRE_CUSTODY=1 QV_CUSTODY_SIGNER=mpc go test -run TestMeasureClosedLoop ./e2e/custody`.

## One withdrawal: HSM signer vs MPC signer

15 sequential withdrawals after a warm-up one, lowest tier (same test, `TestMeasureClosedLoop`, both modes).

| | HSM | MPC (A, B, cosigner) |
|---|---:|---:|
| Withdrawal reaches `broadcast`, median | 388 ms | 387 ms |
| End to end, median | 412 ms | 409 ms |
| End to end, p95 | 415 ms | 692 ms |
| 20 withdrawals at once, all confirmed | 1.18 s | 2.41 s |

The median is the same: the gateway polls every 200 ms and the workflow every 300 ms, which dominate; one two-party signature
takes about 85 ms (party B's log: `OP_SIGN duration_ms 86`). The MPC tail is longer (p95 +280 ms) and 20 concurrent withdrawals
take twice as long: signatures on one key run in sessions, each with a round trip through B and the cosigner's database.

## Added latency between the parties

Delay added to **every** protocol frame, both directions, by the session proxy (the proxy itself adds about 0 ms; the first row
is through the proxy). 5 sequential withdrawals per row after a warm-up one. "Sign" is the sign job's created-to-done time.

| Added per frame | Withdrawal POST to confirmed (p50) | Sign job (mean) |
|---|---:|---:|
| none (through the proxy) | 470 ms | 186 ms |
| 20 ms | 770 ms | 414 ms |
| 100 ms | 2.01 s | 1.55 s |
| 1 s ("slow peer") | 13.55 s | 13.3 s |

A signature takes roughly 13 frames in each direction in total, so every added millisecond per frame costs about 13 ms: 100 ms
per frame is already 1.5 s of signing. The slow peer still completes inside the gateway's 30 s sign timeout and the parties'
5 s receive timeout (a frame is waited for 5 s, not the whole session); at about 2 s per frame it would not.

## Refresh while withdrawals run

4 refreshes back to back with 13 withdrawals made around them: 3.4 s in all (about 0.8 s each), generation 1 to 5, no sign job
failed or was refused, every withdrawal paid once. A Sign that meets a refresh in progress waits or answers UNAVAILABLE and the
gateway retries; it is never lost.

## Soak: 50 signatures per second for 10 minutes

`TestSoakWholePath`: jobs are written to the queue at 50 per second, 8 gateway workers sign through A, B and the cosigner, each
with its own Postgres guard database. 30 000 signatures.

| | |
|---|---|
| Signed | 30 000 of 30 000 |
| Failed or rejected | 0 |
| Sustained | 49.9 signatures/s (10 min 1 s) |
| Backlog during the run | 5 to 9 jobs open |

| Process | RSS start | RSS after 1 min | RSS end | Threads start | Threads after 1 min | Threads end |
|---|---:|---:|---:|---:|---:|---:|
| party A | 40 MB | 62 MB | 63 MB | 14 | 22 | 22 |
| party B | 39 MB | 56 MB | 58 MB | 14 | 19 | 21 |
| cosigner | 19 MB | 27 MB | 30 MB | 8 | 15 | 17 |
| gateway (one worker) | 20 MB | 28 MB | 30 MB | 9 | 13 | 15 |

`mpc-party` memory is flat after warm-up (A: median 62 MB in the first quarter, 63 MB in the last; B: 57 and 58 MB) and the
threads did not move after the first minute (A 22 and 22). The cosigner and gateway grow by 1 to 3 MB over 9 minutes; that is
within what the Postgres pools and the replay-guard caches explain, but it is the first thing to look at in a longer soak.

## Test durations (this machine)

| Run | Wall time |
|---|---:|
| `make test-custody` in HSM mode (18 tests) | 5 min 8 s |
| All custody tests in MPC mode (24 tests), three runs | 14 min 12 s, 15 min 12 s, 15 min 9 s |
| `make test-mpc-soak` | 10 min 7 s |

## E23-2: 2-of-3 signing through the service

Three `mpc-party` processes A, B, C (dev build, insecure sealer, allow-all authorizers: the measurement is the signing path, not the
cosigner or the HSM) and the caller, on loopback, same laptop. Each row is `Sign` as the caller sees it (gRPC call to the
coordinator, including the signature check and the durable job record), 40 sequential signatures after 3 warm-ups, the 2-party HD
signature of the same processes first (`Derive` done before). `recv_timeout_ms` is 1000 in this run.

| Signature | N | p50 ms | p95 ms |
|---|---:|---:|---:|
| 2-party HD key (A+B) | 40 | 65 | 69 |
| 2-of-3, A coordinates with B (A+B) | 40 | 109 | 112 |
| 2-of-3, B coordinates with C (B+C) | 40 | 110 | 112 |
| 2-of-3, B process killed, A signs with C (A+C) | 40 | 110 | 113 |
| 2-of-3, B stalled (SIGSTOP), A waits one receive timeout and signs with C | 10 | 1144 | 1145 |

Reading: every pair of a 2-of-3 keyset signs in about 110 ms, 1.6-1.7 times the 2-party signature through the service (the
wrapper alone measured 2.0 times, `docs/measurements/mpc.md`; the fixed costs of the service dilute it). The pair does not matter.
A first peer that is **down** (connection refused) costs nothing measurable: A tries the next one at once. A first peer that is
**stalled** costs one `recv_timeout_ms` (the wait for its ACK; 5 s by default, 1 s here) and only that: set it as low as the
slowest legitimate answer of a follower plus its cosigner allows. Once a signing message has been exchanged nothing is retried.

Reproduce: `cd mpc-party && QV_MEASURE=1 QV_MEASURE_N=40 go test ./e2e -run TestMeasureThresholdService -v`.
