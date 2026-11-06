# P7-5a — Bitcoin: deposit outputs and sweeps

This closes the loop: deposit, credit, sweep into the hot shard, withdraw.

## Deposit outputs

`btc_utxos` held only hot outputs. Migration 0015 adds `deposit` and `address`. When the scan credits a deposit (including a coinbase output that
was deferred), `RecordDeposit` ([sweep.go](../../internal/chain/btc/sweep.go)) stores its output in the same transaction, with the path `0/<index>` of
its address and the partition of the sink shard. A deposit booked to suspense is not stored: it stays where it is until a person reviews it.
Withdrawals select `NOT deposit`; a sweep selects `deposit` of one address. A unit test proves neither sees the other's.

## The rule, made neutral

`PlanSweeps` already compared value with `max(min_sweep, k x fee)`. The value is `amount x price`, and Bitcoin's price is 1, so the comparison is in
satoshis and `min_sweep_wei` means satoshis for this family; `EstimateSweepFee` returns satoshis, the current rate times the size of the transaction.
A chain may also say what a sweep can take (`chain.SweepSource`): for Bitcoin that is, per address, the oldest available outputs up to `max_inputs`,
without any output at or under its spending cost (68 vbytes times the current rate). The planner uses that instead of "credited deposits minus
swept". One open sweep per address stays: a deposit that lands meanwhile waits for the next sweep.

## The transaction

`BuildSweep` reserves, one at a time with `FOR UPDATE SKIP LOCKED`, the address's oldest outputs until they add up to exactly the planned amount
(the signing zone requires the intent's amount to be the sum of the inputs). If they do not (the set changed), it reserves nothing and the sweep
ends; the planner plans it again. The one output pays the sink shard the sum minus the fee. Each input is a sign job under the address's own key;
the gateway and cosigner check this as they did in P7-3.

## Ledger

For a sweep of `M` satoshis with fee `f`:

| step | accounts |
|---|---|
| broadcast | sweep -> dep, `M` (in transit) |
| settle | hot -> sweep, `M` (what the chain says moved: the sum of the inputs, from the attempt's payload) |
| settle | fee -> hot, `f` |

The sweep account returns to zero, the fee account holds `-f` (the operator's cost: the customer was credited the whole deposit), and the hot mirror
changes by `-(M - f)`, minus what the chain now holds there. Every move is double entry, so `ledger.CheckInvariants` (the ledger side of `Reconcile`)
stays balanced; the e2e tests check it after each sweep. Chain-balance reconciliation of the deposit addresses is outside this task.

## Settlement

`SettleSweep` calls the cell's `Settler` in its own transaction: the deposit outputs become spent and the sweep's output becomes an available hot
output, which the next withdrawal can spend. The scan skips the sweep's txid (it is one of our attempts), so the output is not booked as funding.

# P7-5b — fee policy and recovery

## Fee ceiling

`sweep_max_fee_rate` (default `max_fee_rate`, never above it) is the most a routine sweep pays. `sweep_urgent_value` (satoshis, 0 = none) is the amount
from which a sweep goes anyway. The market rate is the node's estimate, else `fallback_fee_rate`. Above `sweep_max_fee_rate` routine sweeps are left
out of the plan; a sweep of at least `sweep_urgent_value` goes and pays the market rate; above `max_fee_rate` nothing goes, urgent or not. The adapter
logs one line each time the reason changes (not at each pass). `BuildSweep` checks the same rule again and returns `chain.ErrSweepFeePolicy` if the
rate moved since the plan: the sweep ends and the planner decides again. The `stuck_after_blocks` setting, which nothing read, is gone.

## Bump

`BuildReplacement` for a sweep lowers its one output by the extra fee (a sweep has no change, so the output pays). The new fee follows the same rule as
a withdrawal's and must also stay under the sweep ceiling (urgent sweeps: the cap), under `max_tx_fee_sats` and `max_fee_rate`, leave an output above
dust, and keep the sweep worth it: value at least `max(min_sweep, k x fee)`. Otherwise `ErrCannotBump`: one ALERT, the sweep keeps waiting, nothing is
voided.

## Cancel, and what the ledger does

If one input is refused after another was signed, a cancel is sent: the same inputs, one output to the sink shard, each input under its own deposit
key. When it confirms the coins have reached the hot shard anyway, so **it settles like the sweep**, with the cancel's own fee, through the same
`SettleSweep`:

| step | accounts |
|---|---|
| broadcast of the sweep (if it was ever broadcast) | sweep -> dep, M |
| the cancel confirms | hot -> sweep, M (the sum of the inputs, read from the cancel's payload); fee -> hot, the cancel's fee |

The sweep account returns to zero, the customer's credit is untouched, the fee account holds minus the cancel's fee, and the hot mirror is minus what
the chain holds. The inputs are spent and the cancel's output becomes an available hot output. The sweep row ends `confirmed` with the cancel's txid.
`SweepState.SettlesCancel` is true only for a chain whose cancel moves the coins (one that implements `Settler`), so EVM histories keep the old path.

## Release, refusals, outside spends

A sweep refused with nothing signed gives its outputs back, still marked as deposit outputs, and drops its unsent attempt rows (the same outputs
build into the very same transaction later, and a transaction has one row). The planner sees the outputs again, but leaves the address alone after a
failed sweep: `sweep.retry_after` (default 1 minute) doubling for each failure in a row up to an hour. A refusal by the gateway's `sweeps_per_hour`
is such a failure: retried later, never voided, nothing lost. An input of a reserved deposit output spent by something outside this system parks the
sweep with an ALERT (releasing nothing); withdrawals from the hot shard are not affected.

## `sweeps_per_hour`

The gateway limit counts transactions, and the planner makes one per deposit address per round. A deployment needs at least the number of deposit
addresses it expects to sweep in an hour (plus bumps, which count again), with headroom for the retry after a refusal. Too low a value does not lose
money: the sweeps wait, back off, and go in the next hour.
