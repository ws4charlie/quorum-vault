# P7-4b — Bitcoin: fee bumps, cancel, outside spends, crash boundaries

Everything that can go wrong with a Bitcoin withdrawal after it is built ends in exactly one payment, or none, and a balanced ledger.

## Fee bumps

`BuildReplacement` ([bump.go](../../internal/chain/btc/bump.go)) spends the same inputs and pays the same payment from less change. Bitcoin Core
accepts a replacement (BIP125, and every input signals RBF) only if it pays an absolute fee at least the old one's plus the relay cost of its own size at
the incremental relay fee (1 sat/vB), and a higher fee rate. **The rule used:** the new fee is the largest of

- old fee + 15 percent,
- old fee + vsize x 1 sat/vB (BIP125 rules 3 and 4),
- the current fee rate x vsize (what the node would ask for now),

and the extra comes out of the change. If the transaction has no change output, if the change would fall to dust (294 sats), or if the fee would be above
`max_tx_fee_sats` or `max_fee_rate`, it returns `chain.ErrCannotBump`. The workflow's stuck handling (unchanged, time based: `stuck_after`) turns that into
one ALERT ("transaction is stuck and cannot be replaced") and keeps waiting; it never voids a transaction that may still mine. The replacement's jobs
pass the signing zone's own rules: same claims and pins, a new txid, a higher fee.

**The fee actually paid is booked.** `Outcome` looks at every attempt of the owner; whichever is confirmed at the spend depth decides, its txid goes to
`SettleWithdrawal`, `TxFee` is that attempt's fee, and `Settle` spends the inputs and records *that* attempt's change. If the original confirms after a
replacement was broadcast, the original's fee and change are booked (the miner that never saw the replacement; tested with `generateblock`), and the
replacement is gone from the node. If the replacement confirms, its are.

## Rejections by the node

`classifySend` maps the node's answer to `sendrawtransaction`. Already in the mempool, known, or in a block: success. Inputs missing or spent
(`chain.ErrInputsSpent`): nothing is sent, and the outcome check decides who spent them. Everything else the node refuses (a fee below the relay or mempool
minimum, the replacement rules, a conflict with a pending transaction of ours) is `chain.ErrBroadcastStuck`: the attempt is stuck, not failed, and the stuck
handling bumps it. `SubmitJob` returns no hash for either, so the activity does not retry them for ever. A transport error is returned as it is.

## Rebroadcast

`Broadcast` keeps the raw signed transaction and when it was last sent. `Outcome` (polled by the workflow) sends the newest attempt again when the
node does not know it (a restart with an empty mempool, an eviction), at most every 20 seconds. Tested by restarting the compose bitcoind (it runs with
`-persistmempool=0`, so a restart leaves the mempool empty).

## Consumed

If none of our attempts is in a block and an input of the newest attempt is gone from the chain (`gettxout` without the mempool is null), something we
did not make spent it: `Outcome` is consumed, and the workflow raises the same ALERT and parks as on EVM. An input our own attempt spent in a block, one our
own mempool transaction holds, and a confirmed cancel of ours are not this case. If a reserved output is gone before anything was built from it, the
release refuses (`ReleaseUnsigned` keeps the reservation) and the withdrawal parks too.

## Cancel

A refusal after a signature may exist is no longer parked. `EnqueueCancel` builds a cancel when any job of the owner is being signed, done or failed (the
same test as `ReleaseIfUnsigned`, in one helper); when none can have a signature it says there is nothing to free, and `NothingToFree` releases the
reservation instead (rejecting pending siblings in the same transaction). `BuildCancel` spends exactly the attempt's inputs back to the partition's own
shard, one output, for more than the highest fee any attempt paid, so it replaces whichever is pending. It is signed through the gateway (the guard's strict
cancel rule: every claim exists, one signed intent, the same partition, all of that intent's inputs) and broadcast. The money is released only when
the cancel is confirmed at the spend depth: `VoidWithdrawal` then settles the cancel (its inputs are spent, its output is a new available output of the
shard) and records its fee. Once the cancel is confirmed, nothing else can spend the inputs, so the half-signed transaction can never confirm.

**A signature that may exist under claims the guard never took.** The guard records the claims before the signer runs, so no signature exists
without them. But a job in `signing` or `failed` whose gateway died before reserving looks the same as one that signed. For such an attempt the cancel is
built, and the guard's strict rule refuses it (`replay_cancel_claims`: the inputs are not claimed). A refused cancel parks the withdrawal with an ALERT, as
on EVM, and releases nothing. An operator waits for the lease to run out (the gateway reclaims the job and either signs it, and then the cancel can pass
once it has recorded the claims, or refuses it) and resumes the row. If the inputs cannot pay a cancel's fee, the cancel cannot be built
(`chain.ErrCannotBump`): the workflow parks too.

## Crash boundaries

Failpoints (worker built with `-tags devauth`): after build, after sign, after broadcast before recording, after confirm before settle, and after a
cancel was sent. Each test kills the worker there, restarts it, and checks one payment on chain, one send attempt, the hot mirror, the outputs and the
ledger. Also: a gateway killed in the middle of an attempt and restarted (the stored signature of the signed input is replayed), a node restarted
with an empty mempool, and a withdrawal parked when a key signed outside this system.

## Shared code

The refusal path is shared with EVM, and stays behind what a chain supports: `Releaser`, `Settler` and the typed errors exist only for Bitcoin, the
EVM cell implements none of them, and the recorded workflow histories still replay.

`make test-e2e-btc-recovery`, CI job `e2e-btc-recovery`.
