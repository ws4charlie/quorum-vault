# P7-6a — Bitcoin: reconciliation and hot-to-cold

## Reconciliation against the chain

`Reconcile` used to skip its chain checks for Bitcoin. Now three sources must agree: the ledger, the output table (`btc_utxos`), and the chain.

- **The chain is read from the node, not from our tables.** `Adapter.ChainView` runs `scantxoutset` for a set of addresses (100 at a time; the node is
  busy during a call, so it is never on a request path) at the node's tip and reports the height.
- **In flight is computed, not skipped.** The books and the chain differ only by things the cell can name from `btc_attempts` (every transaction it sent,
  with its inputs and outputs) and from what the books booked at broadcast. For the comparison:
  - a table row whose output is gone from the chain is explained when a confirmed transaction of ours spends it (`SpentInFlight`, taken out of the
    ledger side);
  - an unspent output that is not in the table is explained when it is an output of a transaction of ours that the books have not settled
    (`btc_attempts.settled_at`, migration 0016; an output to a cold address is counted only after settlement) or is younger than the credit depth
    (not credited yet);
  - what a sweep (sweep -> dep) and a move (tocold -> hot) booked at broadcast is undone on the ledger side, and the clearing accounts are expected to
    hold exactly the broadcast, unsettled amounts.
  Everything else is a real difference, in flight or not.
- **Consistent reads.** The safe head and a stamp of the books are read before and after; if a block or a change in the books arrived during the read it
  is repeated, up to 3 times. Only then is the comparison skipped, and the report says so (`skipped_chain_checks`) and is **not Clean**. Skips that last
  longer than `reconcile.max_skip` (default 15 minutes) raise an ALERT.
- **Checks:** `hot` (ledger against chain, per shard), `cold` (what moves delivered, against the cold address), `deposit_addresses` (suspense included,
  it stays on its address), `hot_outputs` and `deposit_outputs` (table against ledger, suspense left out) and `outputs_on_chain` (row by row: a row not
  unspent on chain and not explained, a differing value, a hot-address output the table does not hold, a deposit-address output no deposit of ours
  explains).
- A difference names the address, both figures and the height it read, logs an ALERT, and changes nothing. The scan-caught-up check is separate: while the
  scan lags behind the safe head the report is not clean.

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
