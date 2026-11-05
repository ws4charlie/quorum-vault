# P5b-5 — The whole custody system on two-party MPC

Until now the MPC signer (P5b-1..4) was tested with one signature at a time. This task runs the *closed loop* on it:
deposits, sweeps, withdrawals, every crash boundary, and new failure tests, with the hot keys held as two shares in two
SoftHSM tokens. Nothing in the product was redesigned; one real bug was found (below).

## What was built

| Piece | Where |
|---|---|
| Signer mode switch `QV_CUSTODY_SIGNER=hsm\|mpc` | [harness_test.go:67](../../e2e/custody/harness_test.go), hot-key block at [:351](../../e2e/custody/harness_test.go) |
| Test support: parties A and B, cosigner, session proxy | [e2e/mpcstack/stack.go](../../e2e/mpcstack/stack.go) |
| New failure tests (mpc mode only) | [e2e/custody/mpc_test.go](../../e2e/custody/mpc_test.go) |
| Soak (off by default) | [e2e/mpcsign/soak_test.go](../../e2e/mpcsign/soak_test.go) |
| CI job `mpc-e2e` | [.github/workflows/ci.yml](../../.github/workflows/ci.yml) |
| Bug fix: resume of a parked row | [internal/custody/txtrack.go:115](../../internal/custody/txtrack.go) |
| Numbers | [docs/measurements/mpc-service.md](../measurements/mpc-service.md) |

## How mpc mode works

In `mpc` mode `newSystem` starts party B, then party A (each unseals its share with its own token: `qv-party-1`, `qv-party-2`),
runs DKG, and *derives one key per hot shard* (`m/44'/60'/0'/i`). The hot address is the address of the derived key. The gateway
config gets `backend: "mpc"` signers; the cosigner (B's gate) gets a copy of the same rules **without** signer entries, and its
own guard database. Everything else (Temporal, Redpanda, anvil, the workflows) is unchanged, so every existing test runs
unmodified in both modes. Binaries are the *production* `mpc-party` (no failpoints, no insecure sealer).

The proxy ([stack.go `Proxy`](../../e2e/mpcstack/stack.go)) sits between A and B at the session layer and can add delay per frame,
cut the link, or flip one byte in one protocol message. Crashes are real `SIGKILL`s.

## Rules every failure test checks

1. An outage only **delays**: no sign job ends `failed` or `rejected` because a component was down.
2. One `ALERT signer unavailable` per outage, then the job completes after recovery.
3. At most one payout; the hold stays until the nonce is settled or provably cancelled.
4. `Reconcile` is clean at the end.

Waits are on conditions (a log line, a row, a health answer). A slow CI runner only makes them longer.

## Tests and what they show

| Test | Fault | Result |
|---|---|---|
| `TestMPCKillSigningComponentAtCustodyBoundary` | A, B or cosigner down when the worker dies at `after_build` (nonce allocated, no job yet) | withdrawal waits, one ALERT, completes after restart |
| same | component killed when the worker dies at `after_job` (signature exists) | payout completes *without* the component |
| `TestMPCKillPartyMidSession` | A or B killed inside a signing session | job retried, one payout |
| `TestMPCPartitionBetweenPartiesDuringWithdrawal` | link cut before / during a session, healed | waits, completes |
| `TestMPCWithdrawalLatencyWithSlowLink` | +20 ms, +100 ms, 1 s per frame | slower, never fails |
| `TestMPCRefreshDuringLiveWithdrawals` | 4 refreshes while withdrawals run | none fails or is refused |
| `TestMPCFreezeDuringLiveWithdrawals` | tampered message freezes the keyset | see next section |

## The freeze case, and the bug it found

A frozen keyset makes every sign job `failed`. The workflow retries once, then asks to **cancel the nonce**; that is a signature
too, so it fails as well, and the row is **parked** (`failure_reason` starts with `parked:`) with its hold and nonce kept.
That is right: the money must not return while the transaction might still mine.

The documented way out is: unfreeze, then clear `failure_reason`. That did not work: the restarted workflow met the old retry
jobs, already `failed`, and failed again at once, so the row parked again forever. The fix is in
[`RequeueJob`](../../internal/custody/txtrack.go): a retry job that exists and is `failed` is reopened (same digest, so the
gateway can only give the same signature).

After the fix, resume ends like this: the gateway had reserved the **cancel** while frozen, so the original transaction can never
be signed (it would race its own cancel). The cancel is signed, mines, and only then is the hold voided. Later withdrawals
queue behind the open nonces (anvil keeps a gap in the nonce sequence pending) and proceed once the gap is filled.

## Gotchas hit

- `e2e/mpcsign` still used the insecure test sealer, which P5b-4 made development-only: the suite had stopped passing. It
  now uses the real PKCS#11 sealer (via `mpcstack.SealerConfig`).
- `withdrawal.after_job` fires only *after* the signature exists, so "component down at after_job" cannot block signing. The
  test says so and checks the opposite property (completion without the component).
- The gateway's sign timeout was 3 s for the HSM; two parties need more on a slow runner. mpc mode uses 30 s.

## Quiz

1. Why does the cosigner config in mpc mode have no signer entries?
2. Why does the harness use the production `mpc-party` binary and not the `devauth` one?
3. At the `after_job` boundary a party is killed. Why does the payout still complete?
4. What are the four rules every failure test checks?
5. Why does a frozen keyset end with a *parked* withdrawal and not a voided one?
6. Why did "clear `failure_reason`" not resume the row before the fix?
7. After resume, why are the holds voided instead of the withdrawals being paid?
8. Why can a later withdrawal sign but not mine while two nonces are open?
9. What does the proxy's `Tamper` do, and what does it cause?
10. Why are waits on conditions and not on sleeps?

<details><summary>Answers</summary>

1. The cosigner only judges requests; it never signs. Signer entries are the gateway's business and would give B's gate extra authority and config to keep in sync.
2. Failpoints and the insecure sealer must not exist in a production binary; the tests should exercise what ships. Crashes are done with `SIGKILL`.
3. The job is already `done`; broadcasting needs no signer.
4. Outage only delays (no failed/rejected job), one ALERT per outage, at most one payout with the hold kept until settled, clean `Reconcile`.
5. Voiding releases the customer's money; while the nonce is open the transaction may still mine, so the hold stays until an operator resolves it.
6. The retry jobs were already `failed`, a terminal state, so the second failure came instantly and the row parked again.
7. The gateway reserved the cancel for that nonce, so the original can no longer be signed. The cancel mines, then the hold is voided.
8. The chain mines nonces in order; the gap stays pending until the earlier nonces are filled.
9. It flips one byte in the n-th protocol message; the receiving party detects a cryptographic failure and freezes the keyset on both sides.
10. A fixed sleep is too short on a slow machine and wastes time on a fast one.

</details>
