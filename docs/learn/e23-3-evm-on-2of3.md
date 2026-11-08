# E23-3 — EVM hot keys sign 2-of-3

Every EVM hot shard is now a 2-of-3 keyset on `mpc-party` A, B and C. Any one party can be down, patched or replaced and withdrawals
keep going. Bitcoin is unchanged (two-party HD keyset, A and B).

## Who does what

```
 gateway ──► A ──► B or C         first choice: A coordinates with B, else with C
    │
    └──────► B ──► C              when A does not answer: B coordinates with C
```

- **The gateway's signer** (`internal/mpcsigner/threshold.go`, config `scheme: "ecdsa-2of3"` in `signers`) calls coordinator A, and B only
  when A cannot start a signature. The key it checks the hot address against at start is the keyset's public key.
- **A and B coordinate; C only follows.** A authorizes with `pinned-caller`; B and C each ask their own `qv-cosigner` (own process,
  config file and replay-guard database; same decision code and signing-zone trust roots) in every role, coordinator or follower.
  So every signature passes the gateway's check and at least one independent cosigner's check; with B down, C's cosigner is that check.
- **One keyset per hot shard.** The e2e harness and setup tooling run `DKG` with scheme 2-of-3 and an operator signature for each
  shard; the shard's address is that keyset's address. Factory destinations, pinned destinations and `qv-core` point at the new
  addresses. There is no migration: no production data.

## The fallback rule (and why a job cannot loop)

A coordinator fails in three ways, told apart by the service (E23-2) with `ErrorDetail.code`:

| Failure | Gateway |
|---|---|
| connect failed, or `TRANSPORT` / `UNAVAILABLE` **before any signing message** (no `CodeSigningStarted`) | next coordinator, same round |
| `REFUSED` (a cosigner said no), `CRYPTOGRAPHIC`, `FROZEN`, `LIMIT`, `INTERNAL` | final: nobody else is asked |
| `TRANSPORT` / `UNAVAILABLE` **after** signing started | the rest of the call is pinned to that coordinator and retried there |

`max_retries` counts rounds, as for the two-party signer. A round tries each coordinator at most once, in order, so one `SignDigest` makes
at most `(max_retries+1) x 2` calls and cannot alternate. A second signature over the same digest through B after A failed without a
trace is harmless (same transaction, same nonce); the gateway's guard still refuses a different digest under one job.

`mpc-party` marks failures after the first signing message with `CodeSigningStarted` (this task's only service change besides the checks
below).

## Seeing a degraded period

| Party down | Where it shows | Line to alert on |
|---|---|---|
| A | the gateway starts using coordinator B | `ALERT mpc signer degraded` (gateway log, once per period; `mpc signer recovered` at INFO when A signs again) |
| B | A cannot reach it and uses C | `ALERT mpc party link down` in A's log (peer B), once |
| C | A and B cannot reach it | `ALERT mpc party link down` in A's and B's logs (peer C), once each |

`Health` of any party shows `peers[].reachable`, and per keyset `scheme`, `generation`, `resolved`, `frozen`, `backup_*`. Per transition,
never per withdrawal. A is also marked by the gateway as degraded only when it actually signs through B.

## Tests

`e2e/custody/mpc3_test.go` kills each party in turn while withdrawals run (A: via B+C; B: A+C; C: A+B): every withdrawal settles once,
no job fails, Reconcile is clean, one alert. `TestMPCRestartOfAWhileCIsDown` restarts A while C is down. The older outage tests of
`mpc_test.go` now need two parties (or both cosigners) down to cause an outage; the proxy in front of all three links keeps the
partition, latency and tamper tests meaningful (a tampered session freezes the keyset on all three). `e2e/mpcsign` runs the rogue-party
attacks against B's cosigner and against C's (with B down), a refusal by B that must not fall back, and the one-party-down jobs.
The gateway signer's rule has unit tests for every error kind before and after signing started (`internal/mpcsigner/threshold_test.go`).
