# P3b study guide: the closed loop (deposit, sweep, withdrawal)

Code: `internal/custody/` (accounts, ledger flows, reconcile, API), `internal/workflow/` (Temporal), `cmd/qv-core` (API), `cmd/qv-worker` (workflows), `migrations/0005_closed_loop.sql`, tests in `e2e/custody/`. Built on the ledger (P1), the EVM cell (P2), and the gateway, queue and relay (P3a).

The one test that matters: **kill any process at any step, and the system finishes with money moved exactly once and the ledger equal to the chain.** `e2e/custody` does that, with real Postgres, Temporal, Redpanda, anvil, SoftHSM, gateway and relay.

## 1. The chart of accounts

The ledger sums to zero per (chain, asset). So every holding needs an opposite. Customer liabilities are positive; everything on chain is mirrored by a **negative** account.

| Account | Kind | `allow_negative` | Meaning |
|---|---|---|---|
| `cust:<customer>:<chain>:<asset>` | customer | no | What we owe the customer |
| `dep:<chain>:<asset>` | clearing | yes | Minus the funds sitting on deposit addresses |
| `sweep:<chain>:<asset>` | clearing | yes | Sweeps broadcast, not yet confirmed |
| `wd:<chain>:<asset>` | clearing | yes | Withdrawals settling; the counter account of holds |
| `hot:<partition>` | hot | yes | Minus the on-chain balance of that hot wallet |
| `fee:<chain>:<native>` | fee | yes | Our own native money: funding of the hot wallets, less fees paid |
| `suspense:<chain>:<asset>` | suspense | no | Money received that we have not attributed |

Why negative? If the hot wallet holds 10 ETH, the ledger says `hot = -10`. Then `-hot` is the chain balance, which is exactly what `Reconcile` compares. A customer deposit moves value from "on a deposit address" (`dep`, negative) to "we owe the customer" (`cust`, positive); the pair still sums to zero.

**Where does the gas money come from?** Funding a hot wallet is `Transfer hot -> fee`. So `fee` is positive while we have funded more than we spent, and each fee paid moves it down (`Transfer fee -> hot`). `fee` is the operator's own ETH, shown the same way customers' money is. (The task text called it "minus cumulative network fees paid"; with funding recorded it is funding minus fees, and it makes `-hot` exact for ETH.)

**`fees_unsettled` is not needed.** The fee of a transaction is known the moment it is mined (`TxFee`), and it is booked in the same database transaction as the settlement. There is never a period where a fee is owed but unbooked.

A finding for the lead: the task text writes the withdrawal payout as `Transfer hot -> wd`. `Post` moves the held amount customer -> `wd` (so `wd` is positive), and the chain balance of the hot wallet falls, so `hot` must rise. The correct entry is `Transfer wd -> hot`. That is what the code does; `Reconcile` would fail the other way round.

## 2. Each flow as ledger entries

Every flow is **one database transaction**: the business row, the ledger entries, and the outbox event commit together or not at all. Every ledger operation has an ID derived from the object (for example `wd-out:<withdrawal>`), and the ledger ignores a repeat of the same ID with the same body. So any flow can run twice safely.

Amounts: `A` = amount, `E` = expected sweep amount, `M` = what the chain says moved, `f` = fee.

### Deposit credited (scan)
| Entry | Why |
|---|---|
| `dep -> cust` A | Customer address, amount at or above `min_deposit` |
| `dep -> suspense` A | Below `min_deposit`, or the address is unknown |

The scan inserts deposits by `dedup_key` (`chain:tx:log_index`), credits the new ones and moves the cursor `chain_cursors.next_height` in the same transaction. A scan that crashes and repeats finds the rows already there and credits nothing twice.

### Sweep broadcast
`sweep -> dep` E. The funds are leaving the deposit address; they are in transit.

### Sweep confirmed
A sweep moves the forwarder's **whole balance**, so the amount planned is not the amount moved. The contract emits `Swept(token, amount)` per flush, and the adapter reads it (`MovedAssets`, only from known forwarders).
| Entry | When |
|---|---|
| `hot -> sweep` M (per asset moved) | always |
| `sweep -> dep` (M - E) | M > E: a deposit landed meanwhile; later credited by the scan |
| `sweep -> dep` M (other asset) | ETH that rode along with a token sweep |
| `dep -> sweep` (E - M) | M < E: reverse the difference, `sweep` returns to zero |
| `fee -> hot` f | always, fee of the sweep transaction |

Excess that no deposit explains (ETH sent by an internal call, so the scanner never saw it) is found by **true-up**: once the scan cursor has passed the sweep's block, any moved amount above the recorded deposits is booked `dep -> suspense` and recorded as a deposit with origin `unexplained`.

### Withdrawal requested (API)
`Hold cust (counter wd)` A. Insufficient available funds: `ErrInsufficientFunds`, nothing is written, HTTP 409.

### Withdrawal confirmed
`Post` the hold (`cust -> wd` A), then `wd -> hot` A, and `fee -> hot` f.

### Withdrawal failed
`Void` the hold. A reverted transaction or a cancel still paid a fee, which is booked too (`fee -> hot`).

## 3. Why Temporal, and what "deterministic" means

A workflow is a function that Temporal can **replay**. If a worker dies, a new one re-runs the function from the start against the recorded history of what already happened; every activity result is taken from history, not executed again, until the function reaches the first step that has no result yet. For that to work the workflow code must make the same decisions every time.

Rules the code follows (`internal/workflow/workflows.go`):
- No wall clock: `workflow.Now`, `workflow.Sleep`, never `time.Now`.
- No randomness, no map iteration that changes behaviour, no goroutines of its own.
- No I/O. Database, chain and filesystem are touched only inside **activities** (`activities.go`).
- Timings that vary come in as part of the input (`Input.T`), so they are in the history.
- Signals are read through channels, so they are in the history too.

Activities are **at least once**: Temporal retries one after a timeout or a worker death, so each is idempotent. Examples: `BuildWithdrawalJob` returns the existing job if the row already has one (so the nonce is not allocated twice); `BroadcastJob` re-sends the same signed bytes and "already known" counts as success; `SettleWithdrawal` repeats ledger operations whose IDs already exist.

`internal/workflow/replay_test.go` replays real histories (recorded from an end-to-end run, in `testdata/`) against the current code. If someone changes workflow logic in a way that breaks running executions, this test fails.

One workflow per business object; the workflow ID equals the object ID (`wd-...`, `sw-...`). Starting a workflow that is already running is a no-op (`USE_EXISTING`), so "start it" is always safe. Three per-chain loops run beside them (scan, sweep planner, withdrawal reconciler); they continue-as-new so their history stays small.

## 4. The withdrawal, step by step

1. **API** (`POST /v2/withdrawals`, header `Idempotency-Key`): in one transaction insert the row, place the hold, write the outbox event; then start the workflow. The ID is derived from the key, so a retry lands on the same row. If the process dies between commit and start, the **reconciler** workflow starts every open withdrawal that has no workflow.
2. **Approvals.** The API shows the exact intent and its hash (`GET .../intent`); approvers sign the hash with Ed25519 and post it. The initiator cannot approve. Lowest tier: the worker's automated key approves. The workflow re-reads the database on a timer as well as on a signal, so a lost signal only delays. Timeout or a human rejection voids.
3. **Hot liquidity.** The partition (shard) is part of the signed intent, so it is chosen when the request is made (most free hot balance). If it cannot pay yet, the workflow logs an ALERT and retries on a timer, up to `hot_wait`. This is a deliberate deviation from "pick a shard in the workflow": approvers sign the partition, so it cannot change afterwards.
4. **Build + enqueue in one transaction**: the adapter allocates the nonce inside the caller's transaction, and the sign job is inserted in the same one. Either both exist or neither.
5. **Wait for the job** (a polling activity that heartbeats). `done`: continue. `rejected`: cancel the nonce, then void. `failed`: wait `sign_timeout`, enqueue the same digest once more (the gateway returns the same signature, never a second one); a second failure goes to cancel.
6. **Assemble and broadcast**, then record the hash.
7. **Wait for the transaction.** Stuck past `stuck_after`: build a replacement (same nonce, fees up by at least 15%), a new job with the same intent and approvals, broadcast. **Every attempt is checked**, because any of them may be the one that mines (`NonceState` looks at the original, every replacement and any cancel).
8. **Confirmed**: settle. **Reverted**: void and book the fee (the customer can spend the amount again). **Forgotten by the node** (pool restart, `anvil_dropTransaction`): it is just a stuck transaction; `stuck_after` plus a replacement rebuilt from stored data handles it. **Nonce consumed**: the chain's nonce passed ours and none of our attempts mined, so a transaction this system did not make used it, which means the hot key signed something outside the system. The workflow logs `ALERT ... possible key compromise` once, keeps the hold, **parks** the row (`failure_reason` starts with `parked:`) and ends with a non-retryable error. The reconcilers skip parked rows, so it is not restarted and does not repeat the alert; an operator clears `failure_reason` to resume. A refused cancel parks the same way.
9. **Stuck for good**: when replacements run out, or the fee cap stops a replacement, the workflow logs one `ALERT` and keeps waiting. It never voids, because the transaction may still mine.

Before sending a job, `BroadcastJob` checks the nonce: if it is already decided (a replacement mined, say, and this workflow is a fresh execution starting from the first job), it sends nothing and the wait loop reports the result. Without that check the send would fail with "nonce too low" for ever.

### The rule that prevents paying twice
**Never void until the original can no longer mine.** `VoidWithdrawal` itself refuses (`ErrNonceOpen`) while the withdrawal still has a nonce allocation that is not final. After a cancel, void only when a transaction at that nonce has confirmed, and look at **which** one: if the withdrawal itself mined, settle it instead. A nonce that was signed but never broadcast is still a live signature, so it is treated the same way: it must be resolved (mined, or cancelled by a mined cancel) before the money is released.

## 5. Every crash boundary, and why it is safe

The worker exits at a named point when `QV_FAILPOINT=<kind>.<point>` is set (`internal/workflow/failpoint.go`); the test restarts it without the variable. All seven cases below pass in `TestCrashAtEveryBoundary`.

| Boundary | State at the crash | What recovery does | Why money moves once |
|---|---|---|---|
| `withdrawal.after_build` | Nonce and job committed together; workflow does not know | Activity retried: row already has a job, returns it | The job ID is fixed (`wd:<id>:a1`) and the build is skipped, so no second nonce |
| `withdrawal.after_job` | Gateway signed; worker had not acted | Poll again, sees `done`, goes on | The signature is stored on the job; nothing is signed again |
| `withdrawal.after_broadcast` | Transaction sent; hash not recorded on the row | Activity retried: rebuilds the same raw transaction from the stored signature and sends it again; node says "already known" | Same signature, same bytes, same hash; the hash is also in `evm_tx_attempts` (written before sending) |
| `withdrawal.after_confirm` | Transaction final; ledger not yet settled | Poll sees it final again, then settles | Settlement is keyed by withdrawal ID; no payout is booked until then |
| `withdrawal.after_settle` | Ledger committed; activity result lost | Settle retried | Every ledger ID already exists with the same body: no-op |
| `sweep.after_broadcast` | Sweep sent; "in transit" entry not booked | Broadcast retried, then the settle step books the broadcast first if it is missing | Entries use IDs derived from the sweep ID |
| `sweep.after_settle` | Ledger committed | Retried | Same IDs, no-op |

Also tested: kill the **gateway** with a job waiting (the job stays queued; restart signs it), kill the **relay** (events stay in the outbox, drain on restart, each consumed once after de-duplicating on the event id), duplicate API requests (same key, even concurrent: one row, one hold), duplicate approvals and signals (the row is the state, so repeats change nothing).

## 6. Reconciliation

`custody.Reconcile` checks at a pinned safe height and fixes nothing, whether or not anything is in flight:
- `-hot:<partition>` equals the on-chain balance of the hot address, per asset (fees make ETH exact);
- `-dep` equals the sum of on-chain balances of all deposit addresses;
- for every cold address, minus the cold accounts that deliver to it equals its on-chain balance;
- every clearing account (`sweep`, `wd`, `tocold`, `rebal`, `refill`) is zero;
- `ledger.CheckInvariants` passes;
- the scan has caught up to the pinned height (else the chain has deposits the books have not seen).

A live system is never quiet, so the books and the chain differ at almost any moment, and `reconcileEVM` explains the difference from the rows
the cell holds instead of skipping the check. Three things make them differ:

- a transaction of ours mined at or below the pinned height and not settled yet: the chain has its effect, the books get it at settlement;
- a transaction the books booked at broadcast (a sweep, a move, a rebalance, a refill) that has not mined yet: the books have its effect, the chain
  does not;
- a revert that was settled as soon as it was mined, before its block was final: the books have its fee, the chain at the pinned height does not.

For every open item the cell's records (`evm_tx_attempts` through `evm_nonce_allocations`, and the refill's own hash) say which attempt has a receipt at or
below the pinned height; only one attempt per nonce can mine, so a replacement or a cancel is found the same way. Then the books are put in the terms
of the chain: the broadcast bookings of the items that have not mined are taken out, and the ledger legs that each mined item's settlement will book
(what a sweep moved, the excess or shortfall, a move's arrival or its undoing, the gas of a reverted transaction or a cancel) are added. What is left is
a real difference and raises the ALERT. `TestReconcileEVMSweepMinedAndUnsettled` settles with the real code after the explanation and checks that the
report stays clean, so the two cannot drift apart.

The reads are repeated when the books change during them (a stamp of the ledger, the items, the attempts and the scan cursor before the height and
after the last read; 3 tries). A comparison that still cannot be made is counted in `skipped_chain_checks` and the report is **not Clean**, as on Bitcoin.

## 7. Deviations and limits worth knowing

- Business-zone approval tiers are an advisory copy; the gateway is the authority. If they disagree the gateway rejects, and the cancel-and-void path cleans up (a test does exactly this).
- The API cannot check approval signatures (the approver public keys live only in the signing zone). A forged approval is refused by the gateway.
- One factory destination means all sweeps land on one shard (`sweep_destination`); other shards are for withdrawals and need funding from the operator. Refilling them (cold tier) is a later task.
- The sweep planner may under-sweep dust that rode along on an earlier sweep; the ledger is still exact because it follows what moved.
- A withdrawal that reverts on chain, a forgotten transaction, a consumed nonce and a restart after a mined replacement each have an end-to-end test (`e2e/custody/failure_test.go`).
- EVM only: `NonceState` reads `evm_tx_attempts`. BTC and Solana will need the same idea behind the adapter.

## Quiz

<details>
<summary>Questions (answers below)</summary>

1. Why is `hot:<partition>` a negative number when the wallet holds money?
2. A sweep expected 100 and moved 130. Which entries book it, and what happens to the extra 30?
3. Why does the withdrawal payout go `wd -> hot` and not `hot -> wd`?
4. Why can an activity run twice, and what makes that safe for `BuildWithdrawalJob`?
5. What breaks determinism in a workflow? Name three things.
6. The worker dies right after broadcasting. What does the retried activity send, and why is the hash the same?
7. When may `VoidWithdrawal` run, and where is that enforced?
8. After a cancel, the withdrawal still ends up `confirmed`. How can that happen, and what must the workflow do?
9. Why is the shard chosen when the withdrawal is requested rather than in the workflow?
10. What does `Reconcile` compare for the deposit addresses, and why can it fail right after a deposit?
11. Why does the API start the workflow after the commit instead of inside the transaction, and what repairs a crash in between?
12. Why does the sweep planner never start a second sweep for the same address and asset?

</details>

<details>
<summary>Answers</summary>

1. The ledger sums to zero, so a positive customer liability needs a negative mirror. `-hot` is then the chain balance.
2. `hot -> sweep` 130, `sweep -> dep` 30 (the excess), after the broadcast entry `sweep -> dep` 100. `sweep` ends at 0. The 30 is credited when the scan finds that deposit; if no deposit explains it, true-up moves it `dep -> suspense`.
3. `Post` moves customer -> `wd` (positive), and the hot wallet's chain balance falls, so `hot` rises. `wd -> hot` zeroes `wd` and raises `hot`.
4. Temporal retries after timeouts and worker deaths. `BuildWithdrawalJob` returns the existing job if the row has one, so the nonce is allocated once and the job body is never rebuilt with different fees.
5. Wall-clock time, random numbers, I/O (database, network), map iteration order that changes decisions, goroutines of its own.
6. The same signed transaction: it is re-assembled from the signature stored on the job. Same bytes, same hash; the node answers "already known".
7. Only when no nonce allocation of the withdrawal is still `allocated` or `broadcast`, which happens when a transaction at that nonce is final. `VoidWithdrawal` returns `ErrNonceOpen` otherwise.
8. A signature existed (or the original was already in the pool) and mined before the cancel. `NonceState` looks at all attempts and reports which one mined; the workflow settles instead of voiding.
9. The approvers sign the intent, and the partition is a field of the intent. Changing it later would invalidate their signatures.
10. `-dep` against the sum of balances of all deposit addresses. It can fail if the scan has not yet credited a deposit the chain already has, so Reconcile also checks that the scan cursor is past the pinned height.
11. A transaction cannot include a call to another system. The reconciler workflow starts a workflow for every open withdrawal that has none, so a missing start only delays.
12. A partial unique index on open sweeps `(chain, from_address, asset)` makes a second insert impossible, and the workflow ID equals the sweep ID.

</details>
