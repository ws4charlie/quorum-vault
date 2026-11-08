# MPC measurements

## E23-1: cb-mpc threshold ECDSA 2-of-3 against the 2-party path (2026-11-08)

Same run, same machine, both columns from `mpc-party/internal/cbmpc/measure_test.go`. cb-mpc v0.2.2.

```bash
cd mpc-party && go test ./internal/cbmpc -run TestMeasure -measure -measure-n 50 -v    # QV_MEASURE_OUT=file also writes the tables
```

Apple M3 Pro, 12 logical CPUs, darwin/arm64, Go 1.27.3. All parties in one process; "in-process" is memory links, "loopback TCP" is real sockets with length-prefixed frames on 127.0.0.1 (no network latency: add rounds x RTT). Latency is wall time of one ceremony, links excluded. CPU is the process's user+system time per ceremony summed over all parties. Bytes are protocol payload sent by one party (mean). Rounds are the longest chain of messages that each wait for the previous one (a Lamport clock carried on every message). Sign p95 ratio threshold / 2-party: 103 / 51 = 2.0 (in-process and loopback). The task limit is 3.

go go1.27.3 darwin/arm64, 12 CPUs, cb-mpc 2f2c4f1, n=50 per row

#### in-process

| Ceremony | N | p50 ms | p95 ms | rounds | bytes sent per party | CPU ms (all parties) |
|---|---:|---:|---:|---:|---:|---:|
| threshold DKG (3 parties) | 50 | 5 | 7 | 8 | 6932 | 17 |
| threshold refresh (3 parties) | 50 | 5 | 5 | 8 | 6858 | 16 |
| threshold self-test (3 pairs) | 50 | 300 | 305 | 33 | 249606 | 371 |
| threshold sign {0,1} | 50 | 100 | 103 | 9 | 124767 | 124 |
| threshold sign {0,2} | 50 | 100 | 103 | 9 | 124766 | 124 |
| threshold sign {1,2} | 50 | 99 | 102 | 9 | 124768 | 123 |
| 2-party DKG (HD keyset) | 50 | 175 | 240 | 3 | 22392 | 186 |
| 2-party refresh | 50 | 109 | 134 | 6 | 4284 | 113 |
| 2-party sign (key already derived) | 50 | 48 | 50 | 6 | 5199 | 50 |
| 2-party derive + sign | 50 | 50 | 51 | 9 | 5316 | 51 |

#### loopback TCP

| Ceremony | N | p50 ms | p95 ms | rounds | bytes sent per party | CPU ms (all parties) |
|---|---:|---:|---:|---:|---:|---:|
| threshold DKG (3 parties) | 50 | 6 | 6 | 8 | 6931 | 17 |
| threshold refresh (3 parties) | 50 | 6 | 6 | 8 | 6858 | 16 |
| threshold self-test (3 pairs) | 50 | 301 | 304 | 33 | 249607 | 369 |
| threshold sign {0,1} | 50 | 100 | 103 | 9 | 124766 | 123 |
| threshold sign {0,2} | 50 | 100 | 103 | 9 | 124768 | 123 |
| threshold sign {1,2} | 50 | 100 | 103 | 9 | 124767 | 123 |
| 2-party DKG (HD keyset) | 50 | 183 | 225 | 3 | 22392 | 189 |
| 2-party refresh | 50 | 118 | 165 | 6 | 4283 | 121 |
| 2-party sign (key already derived) | 50 | 49 | 51 | 6 | 5198 | 50 |
| 2-party derive + sign | 50 | 50 | 52 | 9 | 5317 | 52 |


Reading: threshold signing is about 2x the 2-party latency and CPU, 24x the bytes (it runs 256 base oblivious transfers from scratch on every signature, `SECURE_USAGE.md` "Multiparty ECDSA signing") and the same order of rounds. DKG and refresh are far cheaper than 2-party (no Paillier key). The self-test is three signatures in sequence.

---

## Removed design: 2-of-3 GG20 (tss-lib)

> **History.** GG20 (tss-lib) was removed in P5b-6. It has known attacks (for example TSSHOCK, 2023, against GG18/GG20 implementations) and nothing in the custody path used it any more; the two-party signer is cb-mpc behind `mpc-party`. These numbers describe the removed design and are kept as a record. Current numbers: [mpc-service.md](mpc-service.md).

Produced by `CGO_ENABLED=1 go run ./cmd/mpcbench -n 10 -fresh-preparams` (raw output below, unedited).

- Date: 2026-11-02 21:34 CST
- Machine: Apple M3 Pro, 12 logical CPUs, darwin/arm64 (SoftHSM 2 via Homebrew)
- Go: go1.27.3; tss-lib: github.com/bnb-chain/tss-lib/v4 v4.0.0-20260923032227-f204718ae595
- Pre-params (3 parties in parallel, freshly generated): 5.1s

| Ceremony | N | min ms | median ms | max ms | rounds | messages | bytes |
|---|---:|---:|---:|---:|---:|---:|---:|
| keygen (3 parties) | 1 | 2995 | 2995 | 2995 | 3 | 24 | 1347552 |
| sign {1,2} | 10 | 363 | 367 | 383 | 9 | 20 | 21412 |
| sign {1,3} | 10 | 368 | 375 | 380 | 9 | 20 | 21414 |
| sign {2,3} | 10 | 368 | 375 | 381 | 9 | 20 | 21414 |
| sign {1,2,3} | 10 | 488 | 494 | 574 | 9 | 60 | 64240 |

## Pre-params variance

Safe-prime search is random, so pre-params time varies run to run. Four fresh
runs on the same machine (all three parties in parallel): **5.1 s, 8.7 s,
9.5 s, 16.0 s** (the last from the first `go test` run). Keygen in those
runs: 2.7–3.0 s.

## How to read it

- **Times** are wall clock for one ceremony with all parties in one process
  (in-memory transport, no network). They include tss-lib's zero-knowledge
  proofs but not unsealing (two or three AES-GCM decrypts in SoftHSM, a few ms).
  Keygen excludes pre-params (cached).
- **Rounds** = highest protocol round that sent a message (keygen 3, signing 9).
- **Messages / bytes** count *deliveries*: a broadcast to two peers counts
  twice, as it would on a network. Keygen bytes are large (~1.3 MB) because
  round 1–3 carry Paillier/ring-Pedersen modulus proofs; signing is ~21 KB for
  two parties.
- Full quorum vs threshold: 3 signers → 3× messages and bytes (every
  broadcast reaches 2 peers, 3 MtA pairs instead of 1), ~1.3× latency (the
  Paillier work per party grows with the number of peers, but runs in parallel).
- On a real network add roughly `rounds × RTT`: 9 sequential rounds at 50 ms
  RTT ≈ +450 ms per signature.
