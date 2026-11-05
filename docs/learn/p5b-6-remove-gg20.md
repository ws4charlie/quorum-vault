# P5b-6 — Removing GG20, and a watchdog for stalled loops

After P5b-5 nothing in the custody path used the old GG20 (tss-lib) MPC code. GG20 has known attacks, so it was deleted and
the docs were brought up to date. One new safety net was added: a watchdog for the worker's long-running loops.

## What was removed

| Removed | Why it was safe |
|---|---|
| `internal/mpc` (and `seal`), `cmd/mpcbench` | only the `/v1` demo and its tests used them |
| `internal/signing/mpcgen.go`, the `Quorum` option | GG20-only ideas (hot = 2-of-3, cold = 3-of-3) |
| `tss-lib` and the `agl/ed25519` `replace` in `go.mod`; `qv-party-3` token | nothing else needed them; `go.sum` has no tss-lib line any more |

What stays: the `mpc` value of `domain.Backend`, the `mpc_key_ref` column and the audit event name. Migrations are not touched, and
old rows may exist. The `/v1` demo is HSM-only: creating an `mpc` wallet returns 422 and names `/v2`
([api.go:230](../../internal/api/api.go)). The cold-wallet tests now use an HSM wallet with two approvals, so that
policy still has a test.

## The watchdog

A rare failure in the crash tests: a sweep never appeared within 90 s. The known candidate is a workflow task handed to a worker that
died at that moment; Temporal redelivers it only after a timeout, and nothing moves meanwhile.

[`Watchdog`](../../internal/workflow/watchdog.go) looks every 15 s at the history length of each workflow:

| Workflow | No new history for 2 min | Why |
|---|---|---|
| scan, sweep planner, withdrawal reconciler (loops) | ALERT, terminate that run, start a new one; if one is not running at all, ALERT and start it | every pass is idempotent: it only reads and starts the per-owner workflows |
| a withdrawal or a sweep | ALERT once, nothing else | restarting money movement automatically is a decision for a person; the reconciler already starts workflows that do not exist |

"No progress" means the history did not grow and the run id did not change. A healthy loop writes history every second, and a
withdrawal waiting for approvals or a transaction polls every few seconds, so two minutes of silence is a stall. Flags
`-watchdog-stall` and `-watchdog-interval` on `qv-worker` (0 turns it off).

The test makes a loop really stall: it starts the loop on a task queue nobody polls, so its first workflow task is never taken, and
checks that the watchdog alerts, terminates the old run and starts another
([watchdog_test.go](../../internal/workflow/watchdog_test.go)). Two unit tests with a fake clock cover timing, "not running", and
"owners are only alerted, once".

## CI

Pull requests used to run one 15-minute MPC job. Now four jobs run in parallel, each on its own runner with its own Postgres, anvil
and (for the custody ones) Temporal and Redpanda: `mpc-signing` (`make test-mpc`) and `e2e-evm-flows`, `e2e-evm-tx-failures` and `e2e-evm-recovery` (Make targets `test-<job>`; the groups are named for what they test, the chain first); the groups are listed in the Makefile). The setup steps live once, in the composite action
[mpc-env](../../.github/actions/mpc-env/action.yml). The heavy tests are in `make test-e2e-evm-failure` and run nightly
([nightly.yml](../../.github/workflows/nightly.yml): the signing path and the full custody set, 45 minutes allowed, also runnable on
demand). The `recovery` group keeps a single crash boundary, `withdrawal.after_broadcast`, through `QV_CRASH_BOUNDARIES`. Only `test` is a
required check. One test by name: `make test-e2e-evm TEST=TestName`.

## Quiz

1. Why was GG20 removed instead of kept "for the demo"?
2. Which parts of the old MPC code were deliberately left in place, and why?
3. What does asking the `/v1` API for an `mpc` wallet return now?
4. What does the watchdog use as the sign of progress?
5. Why may it restart a loop but only alert for a withdrawal?
6. How does the test make a workflow stall for real?
7. Why does a long approval wait not trip the watchdog?
8. What does `-watchdog-stall 0` do?

<details><summary>Answers</summary>

1. It has known attacks, and a second MPC implementation in the repo is a second thing to review and to get wrong. Nothing in the custody path used it.
2. The `mpc` backend value, the `mpc_key_ref` column and the event name: old rows and audit entries may still carry them, and migrations are not changed.
3. HTTP 422 with a message that says the demo is HSM-only and that MPC keys are under `/v2`.
4. A growing history length or a new run id for the workflow.
5. A loop pass is idempotent, so a second run does no harm. Money movement is not something to restart without a person looking.
6. It starts the loop on a queue with no worker, so the first workflow task is never picked up and the history never grows.
7. The workflow polls the database on a timer (every few seconds), which adds history events, so it keeps showing progress.
8. Turns the watchdog off.

</details>
