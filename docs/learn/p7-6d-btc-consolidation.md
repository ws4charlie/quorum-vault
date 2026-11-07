# P7-6d — Bitcoin: consolidation

## The problem

A hot shard is a set of outputs. One transaction spends at most `max_inputs` of them (default 20). A shard fed by many small payments can hold enough
value and still fail a withdrawal, because no `max_inputs` outputs can carry it. Consolidation merges the small outputs into one, before that happens.

## When it runs

A planner round (the cold planner's loop, every `cold.plan_interval`) looks at each hot partition and starts a consolidation when all of this holds:

- the partition has more than `consolidate_above` available outputs (not reserved, not deposit outputs, not cold outputs);
- the fee rate is at or below `consolidate_max_fee_rate`; otherwise it waits, and the log says so once per change ("btc consolidation waits");
- no consolidation and no hot-to-cold move is open on the partition (a move is already spending those outputs);
- scanning is not halted (after a reorganization below the safe depth the books are not trusted until an operator looks);
- at least two outputs are worth spending and what they leave after the fee is above dust.

**What it takes.** The smallest available outputs that are worth spending at the current rate (an output worth no more than 68 virtual bytes at the
current rate stays where it is), at most `max_inputs`. The largest outputs stay free for withdrawals, which is why the order is smallest first. One
consolidation runs at a time per partition; the next round starts another if the shard still holds too many outputs. After a failed one (the gateway
refused, an input was taken meanwhile) the partition is left alone for `sweep.retry_after`, doubling for each failure in a row, up to an hour.

## Withdrawals meanwhile

A withdrawal takes the oldest outputs. When the oldest `max_inputs` available outputs cannot carry the payment and the fee but the shard holds more, it takes
the largest instead. The order is decided before anything is reserved. Hot-to-cold moves keep taking the oldest. Outputs reserved by an open
consolidation are not available, so a withdrawal that arrives meanwhile uses the others, and neither breaks the other.

## Config

In the core's `btc` section:

| Setting | Meaning |
|---|---|
| `consolidate_above` | the number of available outputs above which a shard is consolidated; 0 turns it off. When set it must exceed `max_inputs` |
| `consolidate_max_fee_rate` | sat/vB. Required and positive when `consolidate_above` is set, and at most `sweep_max_fee_rate` |

In the gateway's and cosigner's chain section: `consolidations_per_hour` (0 refuses every consolidation, the default when left out). Each bad value refuses to
start, and the message names the setting.

## The signing zone

The kind is `consolidate`. The Bitcoin verifier requires at least two inputs, all at the partition's own shard path (so nothing from a deposit address, a cold
address or another partition), exactly one output, the intent's destination and the output both the partition's own shard, the intent's amount equal to the
sum of the inputs, and the usual fee caps. The gateway and the cosigner then need no approval, check that the sender is one of their hot shards, and count
the intent against `consolidations_per_hour` in their own stores. A new attempt of a known intent (a fee bump) is not counted again. The reason code of a
refused rate is `policy_consolidate_rate`. The EVM verifier refuses the kind.

**What it can cost.** The money leaves the shard's address and comes back to it, so a compromised core or gateway can lose only the fee: at most
`consolidations_per_hour` times `max_tx_fee_sats` an hour, and each under `max_fee_rate`.

## Books

Nothing is booked at broadcast. At settlement the chain cell marks the inputs spent and records the output as an available hot output, and the fee is booked
from the hot account to the fee account (`fee:<txid>`, once). The value of the shard does not change, so Reconcile reads clean at every stage: the inputs are
reserved rows until a confirmed transaction of ours has spent them (then they are taken out of the ledger side), and the new output is an output of ours
that the books have not settled yet (then it is left out of the chain side).

## Bump, cancel, crash

A bump keeps the same inputs and lowers the one output by the extra fee, under the fee caps and `consolidate_max_fee_rate`; it is refused (`ErrCannotBump`, an
ALERT) when the output would fall to dust. A cancel spends the same inputs to one output of the shard, which is the consolidation's own shape, so a settled
cancel books as a consolidation, with the cancel's fee. A job refused with nothing signed gives its outputs back (`ReleaseUnsigned`). The workflow is
`ConsolidationWorkflow`, built like the cold move's: build, wait for the gateway, broadcast, wait, settle; every step is safe to repeat after a crash.

Tests: `internal/chain/btc/consolidate_test.go` (plan, build, bump, cancel), `internal/chain/btc/verify_test.go` (`TestVerifyConsolidation`),
`internal/gateway/btc_consolidate_test.go`, `internal/cosigner/btc_test.go` (`TestCosignerBTCConsolidation`), `internal/custody/consolidations_test.go`, and
`make test-e2e-btc-consolidate` on real mpc-party and regtest.
