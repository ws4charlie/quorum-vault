# MPC measurements (2-of-3 GG20, tss-lib)

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
