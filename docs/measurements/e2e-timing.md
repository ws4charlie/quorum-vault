# Where the end-to-end suite spends its time (P6-fix)

`make test-e2e-evm` (all 32 tests that build a full system, two-party MPC hot keys) on an Apple M3 Pro, everything local. The harness writes
one JSON line per test when `QV_E2E_TIMING_FILE` is set: start-up in phases, the test body with each condition wait of half a second or more
and what it waited on, and teardown. Numbers below are from one run before the changes and one run after.

| | Before | After |
|---|---:|---:|
| Whole suite, wall time | 1096 s (18.3 min) | 687 s (11.5 min) |
| Sum of the 32 tests | 1082 s | 675 s |
| of which start-up (processes, DKG, funding) | 78 s | 78 s |
| of which teardown | 4 s | 4 s |

Start-up is 2.4 s per test and teardown 0.1 s. **Almost all of the time is the test bodies**, and most of that is waiting for the system to notice
that something died.

## Top time sinks before the changes

| Sink | Where | Sum |
|---|---|---:|
| `withdrawal = confirmed` waits (39) | mostly the recovery after an outage or a crash: **29 s** after a component was down (the gateway's 30 s sign timeout: a digest counts as being signed, and a job keeps its lease, for that long), **14 s, 21 s, 31 s** after the worker was killed (the engine waits for an activity's heartbeat or run timeout before it tries again) | 433 s |
| a withdrawal parked, then failed (freeze test) | two retries each waiting the 30 s window | 112 s |
| `... the move to confirm` / `the refill to confirm` after a worker crash | the same engine timeouts, 5 + 4 boundaries | 95 s |
| deposit swept, forwarders swept | planner interval 1 s, one pass per sweep | 54 s |
| 50 customers at once | real concurrency | 40 s test |
| start-up: hot keys (DKG + derive in mpc mode) | 1.7 s each | 53 s |
| start-up: starting gateway, relay, worker, core | | 11 s |
| 1 s-per-frame signatures in the latency test | **a duration the test exists to measure** | 81 s |
| fixed sleeps | `time.Sleep` of 3, 6, 3, 8 s and 5 x 1.2 s | about 30 s |

## What was changed (test configuration only; production defaults are unchanged)

| Change | Why it is safe |
|---|---|
| Gateway sign timeout in mpc mode 30 s -> 5 s (3 s for the HSM, as before), the business `sign_timeout` equal to it, lease = that + 3 s. All stretched by `QV_E2E_TIMEOUT_SCALE` (15 s in CI) | a signature takes about 50 ms; the timeout only has to expire in the tests that test expiry. The slow-link latency test sets 40 s on purpose, and its link tests use 200 ms per frame instead of 500 ms so a session still fits |
| Approval timeout test 5 s -> 2 s; stuck-after 5 s -> 2 s, default 8 s -> 4 s (all scaled) | each only has to elapse; the logic is still exercised by the same tests |
| `Timings.ActivityTimeout` (business config key `withdrawal.activity_timeout`, empty = production): the engine's activity run, build, queue and heartbeat timeouts, 5 s in the e2e harness | the production values (20 s, 30 s, 20 s, 8 s) are the defaults; a too-short value only causes a retry of an idempotent activity. The nonce-wait slice is 2 s instead of 10 s when it is set |
| Sweep planner interval 1 s -> 300 ms | more passes, same logic |
| Fixed sleeps -> waits on conditions: "the workflow has run again" (workflow history grew), "the planner has gone round N more times", and a bounded **holds** check for the two things that must NOT happen | a negative check can only be shown by waiting; it is now 1.5 s scaled instead of 3 to 8 s |

Not changed: services are not shared between tests, there is one anvil and one test at a time, no assertion was removed or weakened.

## Per test, the six slowest before, and after

| Test | Before | After | Why |
|---|---:|---:|---|
| TestMPCKillSigningComponentAtCustodyBoundary | 148.5 s | 71.9 s | 5 s sign timeout, 5 s activity timeout |
| TestCrashAtEveryBoundary (7 boundaries) | 129.7 s | 73.2 s | activity timeout |
| TestMPCFreezeDuringLiveWithdrawals | 113.6 s | 30.0 s | sign timeout (two 30 s retry windows) |
| TestMPCWithdrawalLatencyWithSlowLink | 108.0 s | 106.0 s | measures real signing time with 1 s per frame: kept |
| TestColdMoveCrashAtEveryBoundary | 98.1 s | 57.7 s | activity timeout |
| TestMPCKillPartyMidSession | 68.5 s | 24.2 s | sign timeout |

TestMPCPartitionBetweenPartiesDuringWithdrawal 66.8 -> 24.2 s, TestRefillCrashAtEveryBoundary 68.4 -> 43.7 s.

## What still takes the time (687 s, above the 10 minutes asked for)

| What | Sum | Can it go lower? |
|---|---:|---|
| The failure tests (nightly only), 8 tests | 431 s | the floor is the recovery after a killed worker: about 8 to 11 s per crash (heartbeat timeout, retry back-off, a queue timeout), 18 crashes |
| the slow-link latency test | 106 s | no: 5 runs x 6 settings of 13.5 s at the slowest are the measurement. Fewer runs would change what it reports |
| start-up of 32 systems | 78 s | not without sharing services, which is not allowed. 53 s of it is the DKG of two parties |
| deposits swept and forwarders emptied | about 60 s | planner and mining are already at 300 ms; the rest is the transaction itself |
| 50 customers at once | 36 s | real concurrency on one nonce counter |

**Per CI job**, from the same run (the tests of each group; a job also pays its set-up of a few minutes): `e2e-evm-flows` 17 tests, 178 s; `e2e-evm-tx-failures` 5 tests, 47 s;
`e2e-evm-recovery` 3 tests, 93 s with the whole crash test and about 35 s with the one boundary pull requests run. All are under 5 minutes of test time.
The three group targets were not run separately here; PR CI will show their real times.

## Not done, because it is risky or changes production

- Heartbeats on **every** activity in production code (as the planners now have): a killed worker would be noticed in seconds in production, not only in tests. That is a production
  change and wants its own review. It would take about 5 s off each of the 18 crash recoveries.
- Lowering the activity timeout below 5 s: a slow runner could time activities out for no reason.
- Running tests in parallel or sharing a system between tests: tests would interfere (nonces, one chain, one gateway guard).

# CI speed (CI-speed task, 2026-11-08)

Goal: a pull request should not wait 8.5 minutes for its slowest e2e job. Method: every e2e test now logs one line, always on,

```text
qv-timing test=TestX chain=0.30 db=0.20 mpc-start=1.02 dkg=0.60 xpub=0.01 configs=0.10 temporal=0.00 spawn=0.30 body=4.07 cleanup=0.07 total=6.63
```

(`e2e/phasetime`, used by `e2e/btc` and `e2e/custody`; `QV_E2E_TIMING_FILE` also gets a JSON line with the waits of half a second or more).
Each e2e test binary also prints `qv-timing-main ... build=` for compiling the binaries its tests start. Measured on an Apple M3 Pro with everything
local (Postgres, bitcoind, anvil, Temporal and Redpanda in Docker), every group once, one test at a time.

## Where the time goes (before any change)

| | tests | sum of tests | start-up per test | body per test | cleanup per test |
|---|---:|---:|---:|---:|---:|
| Bitcoin (8 groups) | 91 | 1422 s | 3.0 s | 12.5 s | 0.13 s |
| EVM (3 pull-request groups) | 45 | 619 s | 2.7 s | 10.9 s | 0.16 s |

Start-up per test, Bitcoin and EVM alike: the two parties boot (`mpc-start`) **1.0 s**, the DKG **0.6 s**, qv-core, worker, gateway and cosigner start
(`spawn`) **0.4 to 0.7 s**, the chain (`chain`: wallet, funding, one block; EVM: factory and token) **0.2 to 0.3 s**, a database created and migrated
(`db`) **0.2 s**, the rest under 0.2 s. Start-up is a fifth of the test time; the body is the rest, and the body is mostly the time the system takes
to react (a killed worker is noticed after the activity timeout: 9 to 12 s per crash in the recovery tests).

Per group, before (laptop, one run): see the report's tables; the slowest tests are the reconcile-in-flight tests (34 to 77 s, each with three or four worker
restarts) and, in `e2e-btc-recovery`, the four fee-refusal tests of the previous task (147 s of 330 s).

## What CI did to the EVM jobs

CI set `QV_E2E_TIMEOUT_SCALE=3` "because a shared runner is slower". The scale is a limit on condition waits, but the EVM harness also stretched the
**delays of the system under test** with it: the activity timeout (5 s), the sign timeout (5 s), stuck-after (4 s, 2 s), the approval timeout and the
gateway lease. A killed worker is noticed after the activity timeout, so every crash and recovery test waited three times as long in CI as on a laptop;
the Bitcoin harness never stretched them and passes on the same runners. Run locally with CI's scale, the EVM groups take the time the CI jobs took:

| EVM group | scale 1 | scale 3 (CI) | CI job's test step (run 42438894625) |
|---|---:|---:|---:|
| flows | 352 s | 495 s | 428 s |
| recovery | 189 s | 270 s | 305 s |
| tx-failures | 129 s | 174 s | 185 s |

## What was changed, and what it saved

| Change | Saving (laptop, same groups before and after) |
|---|---|
| Engine delays no longer stretched by the CI scale: `sdur`/`sd` and `holds` use `QV_E2E_DELAY_SCALE` (default 1), the wait limits keep `QV_E2E_TIMEOUT_SCALE` | at scale 3: flows 495 to 322 s (-35%), recovery 270 to 186 s (-31%), tx-failures 174 to 118 s (-32%) |
| The two parties boot while the node/chain and the database are set up (`mpcstack.Start`, then `WaitReady`) | `mpc-start` 1.02 s to 0.01 s plus 0.08 s of waiting: **0.9 s per test**, 136 tests, about 2 minutes of the 35 minutes of the suites |
| Fee-refusal tests of `e2e-btc-recovery`: stuck-after 2 s instead of 4 s (same assertions, same counts) | 147 s to 106 s for the four tests; the group 346 s to 295 s |
| CI image `qv-ci`, services started in the background, no anvil in the Bitcoin jobs (`ci/`, `.github/actions/mpc-env`) | the jobs' set-up was 81 to 104 s of every job; CI will show the new figure |

Whole groups, scale 1 (before, after): btc-deposits 77, 75 s; withdrawals 116, 112; sweeps 267, 249; recovery 346, 295; cold 167, 150; refill 163, 156;
refill-stuck 237, 233; consolidate 183, 174; evm-flows 352, 327; evm-recovery 189, 192; evm-tx-failures 129, 117 (the three EVM groups at scale 3 are above).

## Measured, and not done

| Candidate | Numbers | Decision |
|---|---|---|
| One migrated template database, `CREATE DATABASE ... TEMPLATE` | the database costs 0.17 to 0.21 s per test (create and 19 migrations), now overlapped with the party boot: at most 0.2 s of 12 to 15 s per test | not done: under 2% of a test, and it is hidden behind the boot already |
| One DKG per test binary | the DKG is 0.6 s per test (136 tests: 80 s). Tests that share a root share addresses, xpubs and balances on a shared chain | not done: independence of the tests costs more than 80 s of 35 minutes |
| One pair of parties per test binary | the boot was 1.0 s per test; now hidden behind the database and chain set-up (0.08 s left) | not needed after the overlap |
| Start worker and core in parallel | `spawn` is 0.4 to 0.7 s per test, the gateway, worker and core are waited for one after the other | not done: at most 0.3 s per test |
| Shorter or fewer fixed sleeps | the harnesses sleep only inside retry loops (100 to 200 ms; 1 s while Temporal is not up); the one fixed sleep in a test is 20 s in `TestRefillStuckWithdrawalBumpRefusedByTheNodeThenTheNodeIsRestarted`, three stuck-after intervals of 6 s that must pass before it checks that no bump left a trace. The `holds` (2 to 8 s) are negative checks: shortening them weakens the test | not done |
| Polling intervals of the harness | 100 to 200 ms (a wait is 0.1 s late on average) | not worth a change |
| Recovery waits (9 to 12 s per crash) | the system's own activity timeout of 5 s plus the engine's retry back-off; the production default is longer | not changed: lower values risk retries on a slow runner for no gain in what is tested |
