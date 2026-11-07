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

## The offline signer for Bitcoin (P7-6b-1)

`qv-cold` signs Bitcoin refills from files only, with the same commands as for EVM. `internal/coldsign/btc.go` holds the rules; the package still has no
network client (the import-graph test stays), which also rules out btcd's `wire`, `txscript` and `chaincfg` (they pull in `net`), so the little Bitcoin it
needs (P2WPKH addresses, the SegWit serialization, the BIP143 digest) is written there and checked against btcd in the tests.

**The request** (`qv-cold-btc-request-v1`) is the whole transaction: network, chain, pool, the cold address, every input (outpoint, value, address) and the
outputs. Output 0 is the payment to a hot shard; output 1, if any, is change to the cold address. Revision grows on re-export. The signed file carries the
raw transaction and its id. The offline tool trusts none of it.

**What it checks, from its own config** (`"family": "btc"`): network, chain and pool; the cold address (from the HSM key's public key); every input from the
cold address, none twice, at most `max_inputs`; exactly the payment to a pinned hot shard and at most change to the cold address, nothing else; the
payment above dust and under `max_amount`; the fee under `max_fee_sats` and under `max_fee_rate` (sat/vB, from the size of the signed transaction); every
pinned address and the cold key belong to the network (a config for another network refuses to start); the approvals (distinct configured operators, at
least the threshold, each over this request's hash).

**The fee attack, and the record of outpoints.** A BIP143 signature commits only to the value of its own input, and the signer has no chain. A request
that understates each input in turn, across requests, would gather signatures that combine into one transaction with a fee nobody saw. So the signer
keeps, per outpoint it ever signed, the value it was signed with, the *intent* (the set of outpoints, the payment address and the amount) and the highest
fee. A request that names a signed outpoint with another value is refused. So is one that spends it in a transaction with another intent. A request with
the same intent and a higher fee is a replacement and is signed (at most one of them can confirm: they spend the same inputs); with the same or a lower
fee it is refused. The record is written, with fsync, before the signature exists, under a lock, so a crash cannot leave a signature the record does not
know; the same request again returns the same signed file.

**What a dishonest online side can still do.** The first time an outpoint is seen, its value is taken on trust. If the online side lies about it, the
signature of that input commits to a digest that does not match the chain's: the transaction is invalid on chain, so nothing moves and nothing is lost
(the refill never confirms). The lie cannot be repaired by a second request with the true value: the pin refuses it, so that coin is stuck until the
operators examine the record and remove the entry by hand. It costs a refill and an investigation, not money. Lying about *which address* an input is
from does not help either: every input is signed under the cold key only.

**The operator's steps.**
1. Once: `qv-cold keygen -network <net> -out key.json` in the offline machine's `qv-cold` token. It prints the Bitcoin cold address and the compressed key;
   put the address in the online config (`cold_addresses`) and the gateway, the compressed key and the pinned hot shards in the offline config.
2. For each refill: carry the request file over, `qv-cold inspect -config cfg.json -request req.json` and read the summary (destination, amounts, fee).
3. Each approving operator: `qv-cold approve -operator <name> -key <their key> -request req.json -out <name>.approval`.
4. `qv-cold sign -config cfg.json -request req.json -approval a.approval -approval b.approval -out signed.json`, then carry `signed.json` back.
5. A stuck refill is re-exported by the online side as a new revision with a higher fee over the same inputs, and signed the same way.
