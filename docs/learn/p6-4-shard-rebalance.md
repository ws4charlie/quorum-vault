# P6-4 — Hot shard rebalance: funds follow the load

Every sweep pays the factory's destination, which is one hot shard (shard 0). The other shards only ever pay out, so they run dry
and need manual funding (P3b report, point 4). A **rebalance** moves funds from the fullest shard to a shard that is below its
target, by itself, so the nonce load of withdrawals and sweeps is spread over several hot wallets again. This is the last P6 task.

## The rule

Per (asset, shard) the business config names a **target**: what the shard should hold ([example](../../internal/custody/config.example.json),
`cold.rebalance.targets`: `"ETH"` for every shard, `"ETH/1"` for one; every shard of an asset needs one). Per asset, one planner pass:

1. A shard whose free liquidity (plus what a rebalance is already bringing) is below its target is *short* by the difference.
2. It receives from the shard with the **most free liquidity**, if that shard holds more than **its own** target. Amount =
   `min(short, source free - source target)`.
3. One rebalance is open per source and asset, and one per receiver and asset: two unique indexes in
   [migration 0009](../../migrations/0009_rebalance_moves.sql).

"Free" is the same figure as for a move to cold: hot balance less what open withdrawals have **reserved**, less moves planned or
signing ([freeHot](../../internal/custody/withdrawals.go)). Reserved funds are never moved, and a withdrawal never counts on funds
that are leaving. The receiver pays nothing; **gas is paid by the source**. A token move needs native gas on the source: when the
source has less than the worst-case fee (`max_tx_fee_wei`) the planner skips it with one `ALERT` per outage (table
`rebalance_gas_alerts`), tries the next-fullest shard, and goes ahead when gas is back.

## Rebalance and move to cold: who goes first, and why they cannot fight

Both take money out of the same hot shards, and one could undo the other (rebalance feeds a shard over its high-water mark, the move
to cold takes it out again, the shard is short again, ...). Four rules prevent it; each is tested.

| Rule | How | Test |
|---|---|---|
| Order | the cold planner loop plans rebalances first, then moves to cold | `TestRebalanceAndToColdDoNotFight` |
| One book | a planned or signing move of either kind is already gone from its source (`freeHot`) | `TestRebalanceNeverMovesReservedFunds` |
| No refill for a fed shard | the low-water check counts a rebalance on its way to the shard, the high-water check does not | `TestRebalanceAndToColdDoNotFight` (no refill, no ALERT) |
| Targets between the marks | config requires `low <= rebalance target <= cold target`: a rebalance fills a shard only up to a level below its high mark (so it never triggers a move to cold), and a move to cold leaves a shard at its cold target, at or above its rebalance target (so it never makes the shard short) | `TestRebalanceConfigRefusals` |

Worked example (the e2e test): shards 0/1 hold 100/0 ETH, cold low 5, high 60, target 40, rebalance target 30. Pass 1: shard 1 is short
30, shard 0 has 70 above its target, so 30 go to shard 1. Shard 0 now has 70, above 60: 30 go to cold. End: 40/30, cold 30. Further
passes plan nothing.

## Why no approval

Like a move to cold, a rebalance can only move money between wallets the operator already runs. The **signing zone** pins the
destination: [verifyRebalance](../../internal/chain/evm/verify.go) accepts a transfer only to the hot address of *another shard of the same pool
and asset* from the zone's own `hot_addresses` (partition IDs are parsed: another pool, asset or chain does not count), for exactly
the intent's amount, native or `transfer(dest, amount)` on the configured token. The business side names the destination too, to
build the transaction; if it names another, both zones refuse.

| Check | Where | Refusal |
|---|---|---|
| destination is a sibling shard, amount, native or token call | verifier (gateway and cosigner) | `tx_mismatch` |
| sender is a hot address this zone owns | [decider](../../internal/gateway/decider.go) | `policy_cancel_target` |
| rebalances per hour (`rebalance_per_hour`; 0 refuses all) | the zone's own guard database | `policy_rebalance_rate` |
| amount per rolling day, per asset (`rebalance_daily_cap`; empty or 0 refuses) | same | `policy_rebalance_cap` |

Approvals attached to a rebalance are ignored, as for a move to cold; the two budgets are separate (a test shows one cannot be spent
on the other). The gateway and the cosigner (party B) each enforce all of this from their own config and store, so a rogue party A
gets nothing past B.

## How it is booked

```
broadcast   rebal -> hot(source)   the funds are on their way
confirmed   hot(dest) -> rebal     they arrived; the clearing account is zero again
reverted    hot(source) -> rebal   the broadcast booking is undone; only the fee stays
fee         fee -> hot(source)     the source pays
```

`Reconcile` knows the new clearing account (`rebal:<chain>:<asset>`; zero once the broadcast booking of a rebalance not mined yet is taken out and a mined one is settled for the comparison) and counts open rebalances as in-flight
work. The hot-address checks need no change: each shard's ledger balance still equals its chain balance.

## The workflow

A rebalance is a transfer out of a hot address, so it reuses what a withdrawal has: nonce allocation, `driveTx` (replacement of a stuck
transaction, cancel of a refused one), parking for an operator. It runs from the same long-running loop as the move to cold (watched by
the watchdog), as its own workflow per rebalance. Crash boundaries are the same five with kind `rebalance`
(`QV_FAILPOINT=rebalance.after_broadcast`).

## Also in this task: a cold address is not a forwarder

P6-1 left a hole: nothing stopped an operator from naming a customer's deposit forwarder as the "cold" address. Forwarders pay the
sweep destination, so such a cold address would not keep anything. `Bootstrap` now refuses to start when a configured cold address equals a
row in `deposit_addresses`, and `EnsureDepositAddress` does not issue an address equal to a cold address (one indexed query, no chain call).

## Tests

| Test | Shows |
|---|---|
| [TestRebalanceFeedsADryShardAndWithdrawalsGoThere](../../e2e/custody/rebalance_test.go) | shard 1 starts dry, is fed 80 ETH; a sweep lands on shard 0, a withdrawal is paid by shard 1; no ping-pong. hsm and mpc |
| TestRebalanceAndToColdDoNotFight | the worked example above; no refill, nothing moves again |
| TestRebalanceNeverMovesReservedFunds | a reserved 30 ETH stays; a second pass plans nothing while one is open |
| TestRebalanceTokenNeedsGasOnSource | no gas: one ALERT, no move; gas back: the token moves, the source paid |
| TestRebalanceCrashAtEveryBoundary | worker killed at all five boundaries; one transfer each |
| [evm](../../internal/chain/evm/rebalance_test.go), [gateway](../../internal/gateway/rebalance_test.go), [cosigner](../../internal/cosigner/cosigner_test.go), [rogue A](../../e2e/mpcsign/rogue_test.go) | destination outside the pinned shards (attacker, cold address, sweep destination, other pool, other asset, the source), intent/transaction mismatch, rate, cap with approvals, against real party B |
| [config and migration tests](../../internal/custody/rebalance_test.go) | target outside low..cold target, missing shard target, one shard only; two open per source or receiver refused; cold address equal to a forwarder |

## Gotchas

- A shard that holds less than its target by exactly the fee it paid is short again. That is fine: it asks the fullest shard, which is
  only a source if it holds more than *its own* target, so a pair of shards at their targets never trade.
- The test partitions of the signing-zone harness for a sibling shard and another pool have no key; the mpc stack leaves them out of the
  gateway's copy of the config (the cosigner has them, which is what the rogue-party test needs).

## Quiz

1. Which shard is the source, and when is a shard allowed to be one?
2. Why must a rebalance target be at most the shard's cold target?
3. Why does the cold planner count a rebalance on its way as liquidity for the low mark but not for the high mark?
4. Who pays the gas, and what happens to a token rebalance when that shard has none?
5. What does the signing zone check about the destination, and where does the list of shards come from?
6. Why are approvals ignored, and why is the rebalance budget separate from the to-cold budget?
7. What stops two rebalances from leaving one shard, or feeding one shard, at the same time?
8. What are the three bookings of a rebalance, and which one is undone if the transaction reverts?
9. Why can a cold address equal to a deposit forwarder not be allowed?

<details><summary>Answers</summary>

1. The one with the most free liquidity, and only if that is above its own target.
2. A rebalance fills a shard up to its target; if that were above the high mark, the next move to cold would take the money out again.
3. The money counts for the low mark so no refill ceremony is opened; it cannot be moved on before it has arrived.
4. The source. The token move is skipped with one ALERT per outage, and goes ahead when the source has native gas.
5. That the destination is the hot address of another shard of the same pool and asset, from the zone's own `hot_addresses`.
6. So the rate and cap hold whatever the intent carries; separate so neither path is a way around the other.
7. Two partial unique indexes on open rebalances (per source and asset, per receiver and asset).
8. Broadcast `rebal -> hot(source)`, confirmed `hot(dest) -> rebal`, reverted `hot(source) -> rebal`.
9. Forwarders pay the sweep destination, so anything sent to a forwarder-as-cold would be swept to hot instead of staying cold.

</details>
