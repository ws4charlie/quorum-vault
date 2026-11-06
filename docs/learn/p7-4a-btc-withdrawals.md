# P7-4a — Bitcoin withdrawals

A withdrawal on Bitcoin goes from request to settlement with the crash safety the workflows already give EVM. This is the first half of
P7-4: the happy path and the refusal that leaves nothing behind. Fee bumps, cancel, outside spends and the crash tests are P7-4b.

## The hot wallet is a table of outputs

Migration [0013](../../migrations/0013_btc_utxos.sql). `btc_utxos` holds the hot outputs: chain, txid, vout, value, partition, key path, status
(`available`, `reserved`, `spent`) and the owner that reserved it. `btc_attempts` holds every transaction the cell built, with its txid (the txid does
not depend on the witness, so it is known unsigned), its payload and fee; `broadcast_at` is set when it was handed to the node, and only broadcast
attempts count as attempts.

Outputs get into the table in two ways:
- **Our own change**, when the transaction that made it settles (`Settle` runs in the settlement's database transaction). Change needs no scanning.
- **Operator funding**: a payment to a hot address from outside. `Scan` finds it at safe depth (6) and returns it as funding; the service records it once
  (`RecordFunding`, `ON CONFLICT DO NOTHING`) and only a new one is booked, hot mirror against the operator funding account. The scan skips any transaction
  that is one of our attempts, so our change is never booked as funding, whenever the scan gets to its block.

## Building

[`BuildWithdrawal`](../../internal/chain/btc/withdraw.go), in the caller's transaction:
- Selects the partition's own shard outputs, oldest first, **one at a time** with `FOR UPDATE SKIP LOCKED`, and sets each `reserved` at once. A concurrent
  build sees only outputs nobody has locked or reserved, so two builds never pick one, and a build that rolls back reserves nothing.
- Fee rate: `estimatesmartfee`, else `fallback_fee_rate`, never above `max_fee_rate` (below the gateway's) and never below the relay minimum. Fee =
  rate x virtual size of the witnessed transaction.
- The payment is the first output; change is the second, to the shard's own address, only when it is above the dust limit (294 sats). Otherwise the
  remainder is fee (an exact amount has no change at all). A fee above `max_tx_fee_sats` is refused for good.
- Too few outputs (or more than `max_inputs` would be needed) is `chain.ErrNotEnoughOutputs`: **retryable**. The workflow waits, as it waits for hot
  liquidity, up to `hot_wait`, and builds when an output frees up. It never fails for that.
- The payload comes from `btc.BuildUnsigned`, so the digests are the ones the signing zone recomputes. One sign job per input, all under the shard's key.

## Assembling and broadcasting

`Assemble` makes the witness `[DER(r,s) + 0x01, public key]` of each input and verifies each signature against its digest and key before anything is
serialized. `Broadcast` marks the attempt as broadcast first, then sends; "already in the mempool", "already known" and "already in a block" are success,
so a repeat after a crash is safe. `getrawtransaction` needs the node to run with `-txindex=1` (the compose profile does).

`Status` is confirmed at `spend_confirmations` and pending otherwise (a transaction the node does not know is pending: it can be sent again).
`Outcome` is open or confirmed; `Reservation` is open while outputs are reserved by the owner. `TxFee` is the fee of the attempt, from its payload.

## Settlement depth, and what a reorganization does

A withdrawal settles at **2** confirmations (`spend_confirmations`), not at the deposit depth of 6. Our own transaction spends only our own outputs, which
only our key can spend, so nobody can double-spend it: a reorganization can remove it from the chain for a while, never replace it. After settlement:
- the books stay as they are (the withdrawal is confirmed, the hot mirror and the outputs do not change);
- the transaction goes back to the node's mempool and is mined again, normally in the next block;
- no second payment is made: nothing asks for one, and the change recorded at settlement has the txid of the same transaction.

Tested with `invalidateblock` and empty blocks (`generateblock`) so that the payment is off the chain for a while, then mined again
(`TestReorgRemovesASettledWithdrawalForAWhile`). If a reorganization could ever make such a transaction invalid for good (a double spend of our own inputs),
that would mean the key signed something outside this system: it is what the consumed outcome of P7-4b alerts on.

## Refusals

If the gateway refuses the attempt and **nothing was signed** (every job is rejected, or still pending), `ReleaseIfUnsigned` rejects the pending siblings in
the same transaction (so no gateway claims one afterwards) and gives the outputs back (`available`), then the hold is voided. If a job is being signed, done
or failed, a signature may exist: nothing is released, the row is **parked** with an ALERT, and the money stays where it is. Cancel (P7-4b) will free those.

## Business zone

- Withdrawal destinations are validated by the cell (`chain.AddressNormalizer`): the network's address forms, lower-case bech32, another network refused.
- The `btc` family runs the scan and the withdrawal reconciler loops. `chain.btc` in the core config: `hot_shards` (address and path of each; shard i serves
  partition i), `spend_confirmations`, `max_inputs`, `fallback_fee_rate`, `max_fee_rate`, `max_tx_fee_sats`. The core derives each shard address from its xpub
  at start and refuses a mismatch.
- Generalized for this task (and nothing more): shard count (`Config.shardCount`, `ShardIndex`), the destination check, funding in `ApplyScan`, the settlement
  hook, the workflow's wait for outputs. `Reconcile` still skips the checks that need chain balances.

## Tests

[btc/withdraw_test.go](../../internal/chain/btc/withdraw_test.go) (selection, change, exact, dust, not enough, concurrency, settle, release, assemble with
`txscript`, broadcast, status, funding), [custody/release_test.go](../../internal/custody/release_test.go), and on real mpc-party, regtest:
[e2e/btc/withdraw_test.go](../../e2e/btc/withdraw_test.go): full withdrawal with change then the change spent; two inputs; exact amount and change at dust
with the fee booked; many concurrent withdrawals against few outputs (none shares an output, none fails); waits for an output and proceeds; refused by the
gateway; a reorganization after settlement. `make test-e2e-btc-withdrawals`, CI job `e2e-btc-withdrawals`.
