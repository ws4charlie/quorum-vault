# P6-1 — Hot to cold: the excess leaves the hot wallet by itself

A hot wallet signs all day, so it should hold only what the next hours need. When a hot partition holds more than its
**high-water mark**, the excess moves to a **cold address** without anyone's approval. This is the first of three P6 tasks: P6-2
is the offline cold signer and the refill (cold to hot), P6-3 the factory admin ceremony and shard rebalancing.

## The rule

Per (hot partition, asset): a low mark **L**, a high mark **H**, a target **T** (default halfway between L and H), base units, in
the business config ([example](../../internal/custody/config.example.json)).

| Free hot liquidity | What happens |
|---|---|
| above H | a move of `free - T` to the cold address |
| between L and H | nothing |
| below L | one `ALERT` per outage (the refill itself is P6-2) |

"Free" is the hot balance in the ledger less the liquidity open withdrawals have **reserved** and less a move already planned or
signing, so a move never takes money a withdrawal is counting on
([freeHot](../../internal/custody/withdrawals.go)). Only one move per partition is open at a time (a unique index in
[migration 0006](../../migrations/0006_cold_moves.sql)). The ALERT flag lives in the table `hot_low_alerts`, so two processes do not
both shout and a restart does not repeat it.

## Why no approval

The destination is pinned in the **signing zone's** config (`cold_addresses`, key `<pool>/native` or `<pool>/token`), in the
gateway's and in the cosigner's. The business side only names it too, for building the transaction; if it names another, both
zones refuse. A move can therefore only make funds safer, so a human adds nothing. What they check instead:

| Check | Where | Refusal |
|---|---|---|
| destination, amount, native or `transfer(cold, amount)` on the configured token | [verifyToCold](../../internal/chain/evm/verify.go) | `tx_mismatch` |
| sender is a hot address this zone owns | [decider](../../internal/gateway/decider.go) | `policy_cancel_target` |
| moves per hour (`to_cold_per_hour`) | the zone's own guard database | `policy_to_cold_rate` |
| amount per rolling day, per asset (`to_cold_daily_cap`; empty or 0 refuses) | same | `policy_to_cold_cap` |

Approvals attached to a move are **ignored**: the cap holds whatever the intent carries, so an "approved" move cannot push more through
than the cap. A *withdrawal* that happens to pay the cold address is still a withdrawal: it needs approvals and counts against the
withdrawal caps, not these.

## How it is booked

```
broadcast   tocold -> hot     hot goes down, the clearing account holds minus the amount
confirmed   cold  -> tocold   cold holds minus the on-chain cold balance, clearing is zero again
reverted    hot   -> tocold   the broadcast booking is undone; only the fee stays
fee         fee   -> hot      as for every transaction
```

`Reconcile` adds one check per cold address and asset: the sum of the `cold:<partition>` accounts that deliver to it equals its
on-chain balance. A cold address that is also paid by someone else would fail it, on purpose: this check is about what we moved.

## The workflow

A move is a transfer out of a hot address, so it reuses everything a withdrawal has: nonce allocation, `driveTx` with replacement of
a stuck transaction and cancel of a refused one, parking for an operator. The cold planner is a fourth long-running loop (watched
by the watchdog from P5b-6). A move that fails ends cleanly and the planner plans another if the partition is still above H.
Crash boundaries are the same five, kind `to-cold`.

## Tests

| Test | Shows |
|---|---|
| [TestColdMoveExcessEthAndToken](../../e2e/custody/cold_test.go) | ETH excess at start, USDT excess after a deposit is swept; ledger and `Reconcile` match. hsm and mpc |
| TestColdMoveRespectsOpenWithdrawals | a reserved 30 ETH is not taken: move = hot − 30 − T |
| TestColdMoveCrashAtEveryBoundary | worker killed at all five boundaries; one transfer each |
| TestColdMoveBelowLowRaisesOneAlert | one ALERT per outage across processes and passes |
| [tocold_test.go (evm)](../../internal/chain/evm/tocold_test.go), [gateway](../../internal/gateway/tocold_test.go), [cosigner](../../internal/cosigner/cosigner_test.go), [rogue A](../../e2e/mpcsign/rogue_test.go) | other destination, wrong amount, wrong token call, rate, cap with approvals attached, against real party B |

## Gotchas

- A move was first modelled on a sweep, but a sweep is a call to the factory from deposit addresses; a move is a plain transfer out of
  the hot address, so it follows the withdrawal's building and the sweep's booking.
- The failpoint kind is `to-cold` (`QV_FAILPOINT=to-cold.after_broadcast`).

## Quiz

1. Why does a hot-to-cold move need no human approval?
2. Where is the cold address that counts, and who can change it?
3. What does "free hot liquidity" subtract from the balance, and why?
4. Why are approvals on a `to-cold` intent ignored?
5. What is wrong with `Reconcile` if a customer sends ETH straight to the cold address?
6. Which two components enforce the daily cap, and from what?
7. What stops two moves of one partition running at once?
8. How is the "below L" ALERT limited to once per outage?
9. What happens to the booking if the move transaction reverts?
10. Why can a withdrawal to the cold address not be used to get around the to-cold cap?

<details><summary>Answers</summary>

1. The destination is pinned in the signing zone, so the move can only make funds safer; an approver would have nothing to judge.
2. In the signing zone's config (the gateway's and the cosigner's); the business side cannot change it.
3. Funds reserved for open withdrawals and moves already planned or signing, so a move never takes money someone is counting on.
4. So the rate and the daily cap hold no matter what the intent carries: approvals cannot buy a way past them.
5. The cold check fails: the chain balance is higher than what the ledger says it delivered. That is intended; the check is about what we moved.
6. The gateway and party B's cosigner, each from its own guard database.
7. A unique partial index on open moves per partition and asset, and the planner takes the partition's row lock.
8. A row in `hot_low_alerts` per partition, set when the ALERT is logged and cleared when the balance is back above L.
9. The broadcast booking is reversed (`hot -> tocold`), the fee is booked, the move ends `failed`, and the planner may plan another.
10. It is a different intent kind: it needs approvals and counts against the withdrawal caps, and it does not touch the to-cold budget.

</details>
