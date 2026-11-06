# P7-1 — The chain seam

Bitcoin needs several signatures per transaction and has no nonce. Before this task the signing path, the replay guard and the
workflows assumed one signature and an EVM nonce. Now they ask the chain cell instead, and the EVM cell answers as it always did.
No Bitcoin code is here, and EVM behaviour is the same.

## Several signatures per transaction

`chain.UnsignedTx` lists the inputs to sign: `Digest` and `KeyRef` are the first, `More` holds the others, and `Inputs()` gives all
of them. Each input becomes one sign job ([EnqueueUnsigned](../../internal/custody/txtrack.go)); every job carries the same payload
and the intent's partition, and its own key in `KeyRef`.

- **Job IDs.** The ID of an attempt is the ID of its first job (`wd:<id>:a1`, retry `:a2`, replacement `:r1`). Input `i` after the
  first is `<attempt>.<i>`. A one-signature transaction has the IDs it always had, so workflows already running find their jobs.
  The workflow activities still pass the attempt ID only; the activity looks up the group.
- **State of an attempt.** Any refused job refuses the attempt, at once. Otherwise it is pending until every job is done; one failed
  job fails it. A retry copies every job of the attempt (same digests), so jobs that were signed come back as replays from the
  gateway and nothing is signed twice.
- **Submit.** `SubmitJob` needs all jobs done, then calls `Assemble` with all signatures in input order.
- **Crash between two signatures.** The gateway reserves each digest before signing and stores each signature. A job claimed
  again after a crash is a replay of the stored signature (test `TestCrashBetweenTwoSignaturesSignsEachDigestOnce`).

## What makes attempts exclusive

The gateway's guard had one rule for EVM: one intent per (sender, nonce); a replacement keeps the nonce and raises the fees. The
rule is now stated over **claims**: the codec reads from the payload what the transaction consumes (`TxInfo.Claims`; EVM: one
claim, `<sender>#<nonce>`) and its fee components (`TxInfo.Fees`; EVM: fee cap, tip).

1. A claim is held by one intent. Another intent on a held claim is refused (`replay_nonce_taken`); a cancel may take it over;
   a claim consumed by a cancel stays refused.
2. A known intent may add a digest only over the same claims (`replay_nonce_changed` otherwise).
3. The new digest is either another input of a transaction already being signed (same payload hash; no fee check), or a
   replacement, and then `codec.FeesRaised(previous, next)` must hold (`replay_fee_not_higher`).

The reason codes keep their names so that operators' alerts do not change. The tables are `exclusive_claims` (replacing
`nonce_claims`), `signed_intents.claims` and `signed_digests.fees` and `payload_hash`.

### Upgrade of an existing guard database

`store.sql` runs at every gateway and cosigner start. On a database written before this task it adds the columns, fills `claims`
(`<sender>#<nonce>`) and `fees` (`[fee cap, tip]`) from the old columns, copies every `nonce_claims` row into `exclusive_claims`
and drops `nonce_claims`. It is idempotent, and a no-op on a fresh database. Restart all gateway and cosigner instances that share
a guard database together: an instance of the old version cannot read the new tables. Test:
`TestGuardUpgradeKeepsOldRowsWorking` builds the old schema with an old intent, digest, signature and claim, upgrades it twice,
and checks that the claim, the old fees and the old signature still decide as before.

## Outcome of an attempt, and cancel

`chain.Adapter` has two new methods. `Outcome(owner)` looks at every attempt of the owner and says: open; confirmed (which attempt:
the send or a cancel; failed or not); or consumed by something this system did not make. `Reservation(owner)` says whether the
owner still holds something that a signature might yet use, and names the account. The EVM cell implements them with the logic that
lived in `custody` ([outcome.go](../../internal/chain/evm/outcome.go)). `custody.AttemptState` maps the answer to the state strings the
workflows record in their histories (`mined`, `reverted`, `cancelled`, `consumed`; do not change them).

`BuildCancel` stays optional. If it returns `chain.ErrNotSupported`, `EnqueueCancel` returns no job. `cancelNonce` then does not
assume that the refusal left nothing behind: it asks the chain (activity `NothingToFree`: `Outcome` shows no attempt ever
broadcast, `Reservation.Open` is false). Only then does it finish as "cancelled" and the hold is released. Otherwise it logs an
ALERT, parks the row and fails with the same non-retryable error as a refused cancel; money is never released. EVM never reaches
this branch, so its histories are unchanged.

## Destinations

`AssetPolicy.Destinations` is a set of canonical address strings. `ChainCodec.Canonical` defines the form; for EVM it is the checksum
form, so case never matters. The Decider reads the destination from the transaction, canonicalizes it with the codec and looks it
up. Pinned addresses (hot, cold, sweep) are still checked by each codec's verifier from its own config section.

## Family switch

`ChainFile` (custody) and `ChainFile` (gateway) have `family`, default `evm`. An unknown family is an error at config load, so the
process does not start. `chainfactory.Open` gives `qv-core` and `qv-worker` an adapter and a reader; `gateway.NewCodec` gives
`qv-gateway` and `qv-cosigner` a codec. `EVMReader` is reached through `custody.Reader` only.

### Queue and workflow IDs

A worker serves one chain, on task queue `qv-core-<chain>` (flag `-task-queue` still overrides). Loop workflows carry the chain in
their ID (`scan:<chain>`, ...). Withdrawal, sweep and move workflows are named by their row ID, which is unique in the business
database that the cells share. **Operational change:** the default queue is no longer `qv-core`. When upgrading a running EVM cell, either
drain it first or start both processes with `-task-queue qv-core`.

How it was checked: `TestTwoChainsOnOneTemporalDoNotCross` runs two workers for two chain names on the dev Temporal server, each
with a probe workflow, and starts workflows on each queue: every one is answered by its own chain's worker. It also checks that the
loop IDs of two chains never meet.

## EVM assumptions that are left

P7-2 to P7-6 work from this list. "Row" means the line at the time of this task.

**`internal/custody`**

- Config is the EVM config: [config.go:90-94](../../internal/custody/config.go) (factory, sweep destination, hot shards as addresses, `max_tx_fee_wei`),
  [155](../../internal/custody/config.go) `HotShards []common.Address`, [161](../../internal/custody/config.go) and [112](../../internal/custody/config.go) `MinSweepWei`,
  [189-196](../../internal/custody/config.go) `Asset.Address` (zero = native), [264-278](../../internal/custody/config.go) address parsing, [325-334](../../internal/custody/config.go) `c.EVM`, [433-441](../../internal/custody/config.go) `ShardAddress`, [473-478](../../internal/custody/config.go) cold addresses.
- Fee and value accounting is in wei: [config.go:104-106,192,311](../../internal/custody/config.go) `PriceWei`, [sweeps.go:79-81,158-159,197-198](../../internal/custody/sweeps.go)
  (`valueWei`, `MinSweepWei`: the sweep rule), [rebalance.go:257,268](../../internal/custody/rebalance.go) `MaxTxFeeWei` as the gas reserve.
- Addresses are `common.Address` or checksum hex: [withdrawals.go:133-143](../../internal/custody/withdrawals.go) (request validation: `0x` hex, mixed-case checksum),
  [accounts.go:75,128-129](../../internal/custody/accounts.go), [coldmoves.go:169-182](../../internal/custody/coldmoves.go), [rebalance.go:210-219](../../internal/custody/rebalance.go),
  [reconcile.go:85-117](../../internal/custody/reconcile.go) (`addr.Hex()`, `c.EVM.ColdAddress`), [sweeps.go:256](../../internal/custody/sweeps.go) `EVM.SweepDestination.Hex()`.
- The sweep model is the forwarder: [sweeps.go:171-177,242-244](../../internal/custody/sweeps.go) (`evm.ErrSweepFrozen`, `evm.ErrDestinationMismatch`),
  [accounts.go:67,134-150](../../internal/custody/accounts.go) (`checkColdNotForwarder`).
- Refills and the cold ceremony are EVM only (the `RefillChain` interface and `evm.RefillState`): [refills.go:96-110](../../internal/custody/refills.go), [refills.go:210,499-523](../../internal/custody/refills.go);
  [api.go:369](../../internal/custody/api.go) says "nonce and fees read from the node".
- The reservation error and text still say nonce in places: [service.go:57](../../internal/custody/service.go), [withdrawals.go:529](../../internal/custody/withdrawals.go).
- The evm tables are read by the fake in [custody_test.go](../../internal/custody/custody_test.go) only, not by the service.

**`internal/workflow`**

- [activities.go:379-382](../../internal/workflow/activities.go): a refill broadcast error is recognized by the text "nonce too low".
- Names and texts still say nonce: `WaitNonce`, `NonceResult` ([activities.go:612-622](../../internal/workflow/activities.go)), `cancelNonce` and the ALERT texts ([workflows.go:332-343,372-393](../../internal/workflow/workflows.go)),
  the Temporal error types `nonce_open` and `nonce_consumed` ([activities.go:43](../../internal/workflow/activities.go), [workflows.go:343](../../internal/workflow/workflows.go)). The activity names and error types are in recorded histories; rename them only with a versioned change.
- The refusal path of `WithdrawalWorkflow`, `SweepWorkflow`, `ColdMoveWorkflow` and `RebalanceWorkflow` ([workflows.go:479-482,569,630,674](../../internal/workflow/workflows.go)) assumes that a refused attempt may hold a signature at a nonce and must be cancelled. On a chain without cancel it falls through (tested): it asks the chain first and parks if anything was broadcast or is still reserved.

**Gateway and signing zone**

- `ChainFile.EVM` and `evm.Config` are the only config section ([config.go](../../internal/gateway/config.go)); the destination list rejects the EVM zero address ([config.go](../../internal/gateway/config.go), `AssetFile.build`); `MaxTxFeeWei` is wei.
- Sign jobs for sweeps carry one `From` and one `To` (`signjob.Intent`); a Bitcoin sweep has many inputs under many keys.
- The guard's `signed_intents.nonce`, `signed_digests.nonce`, `tip` and `fee_cap` columns remain (nullable, no longer written) for old rows.
- `internal/coldsign` and `cmd/qv-cold` are EVM only (nonce, gas, factory).
