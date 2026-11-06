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

## Not yet (P7-5b)

A sweep that needs a fee bump or a cancel waits with an ALERT and releases nothing (`chain.ErrCannotBump`). The fee ceiling, the urgent-value
exception and recovery for sweeps come next.
