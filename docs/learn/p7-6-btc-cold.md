# P7-6a — Bitcoin: reconciliation and hot-to-cold

## Reconciliation against the chain

`Reconcile` used to skip its chain checks for Bitcoin. Now three sources must agree: the ledger, the output table (`btc_utxos`), and the chain.

- **The chain is read from the node, not from our tables.** `Adapter.BalanceBatch` runs `scantxoutset` for a set of addresses (100 at a time; the node is
  busy during a call, so it is never on a request path) at the node's tip and reports the height. A balance counts only outputs the books should have
  by now: change and sweep outputs of our own transactions at the spend depth, everything else (deposits, operator funding) at the deposit depth.
- **Checks:** `hot` (ledger against chain, per shard), `cold` (what moves delivered, against the cold address), `deposit_addresses` (suspense stays
  on its address, so it is part of what the chain holds), `hot_outputs` and `deposit_outputs` (the table against the ledger, suspense left out) and
  `outputs_on_chain` (`AuditOutputs`: a row whose output is not unspent on chain, a differing value, a settled output on a hot address that the table
  does not hold). A deposit output without a row is reported only if no deposit of ours explains it.
- A difference names the address, both figures and the height it read, logs an ALERT, and changes nothing.
- With anything in flight (a sweep, a withdrawal, a move) the chain comparisons are skipped and counted, as the clearing residuals are: the books and
  the chain see an output at different depths. Run it when the cell is quiet.

## Hot to cold

The EVM planner, workflow and bands are reused. `chain.btc` now takes `cold_addresses` (`<pool>/native`, checked at start against the network and
against the hot shards; it must equal the gateway's pin). A move is a `to-cold` withdrawal: only the shard's inputs, the cold address first, change back
to the shard. Bumps, cancel, the consumed outcome, release and rate and daily limits are the same code as for withdrawals (the owner kind is the
only difference); unit tests and `TestColdMoveOneInputRefusedAfterAnotherWasSignedIsCancelled` prove it for moves.

**How a large move behaves against `max_inputs`.** One transaction carries at most `max_inputs` inputs. The planner asks the cell what one move can carry
now (`MaxMove`: the oldest available hot outputs, at most `max_inputs`, minus the fee) and caps the move at that. So a shard of many small outputs
goes down in rounds, one move at a time, each taking the oldest outputs; with nothing available it plans nothing and opens no second move. An output
a withdrawal reserved is not available, so a move never competes for it.

**A confirmed cancel of a move** settles as a failed move: the inputs are spent, the output is a hot output, the cancel's fee is booked, the move's
broadcast booking is undone. Nothing reached cold.

**Remaining.** A low-water ALERT is logged but opens no refill yet (offline signing, 6b). Hot outputs still pile up as change and swept outputs; a move
spends the oldest first, but a shard below its high-water mark is never consolidated. A consolidation flow is still needed.
