# Runbook: a hot key may be stolen (emergency)

A hot key signs withdrawals and sweeps all day, so it is the one most likely to be attacked. The design assumes it can be lost and limits the cost: the hot wallet
holds little (the excess goes to cold), the forwarder factory pays only to its destination, and the destination changes only by the cold key. This page is the
procedure for the first hours. Read it before you need it; the steps marked **prepare** must exist before an incident.

**The race.** The thief holds a copy of the key and can sign on chain at any time; nothing we do stops that. Two things decide the loss: how long it takes to
sign the emergency record, and how fast the old address is emptied afterwards. Everything below is ordered by that.

## What can be saved and what cannot

| | |
|---|---|
| **Saved** | whatever is still on the old address when its drain transfer lands; every later withdrawal (it signs from the new key); deposits swept after the new key is the destination |
| **Lost** | what the thief moves **before** the drain lands, bounded by the hot balance; the hot balance is small by design |
| **Exposed until swept** | deposits that arrive later at old addresses that the old key controls (Bitcoin and Solana deposit keys; they are watched and swept at emergency priority, but a thief can spend them first). EVM deposit addresses are forwarders: they pay the factory's destination, not the old key, so a stolen hot key cannot take them |
| **Not stopped** | a transaction the thief signs with the old key is valid on chain; the signing zone refuses it only when it is asked to sign. There is no on-chain brake except the factory's `freeze()` |

## What exists today, per chain and key

"Record" is the one operator-signed `mark-compromised` record (successor and drain caps inside it, the zone decides from it at its next decision).

| Key | In an emergency today | Manual steps left |
|---|---|---|
| **EVM hot shard** (HSM or MPC) | full path: `qv-rekey emergency`; the record stops ordinary signing, allows only the drain to the successor, carries the caps, lifts the hourly drain rate; core stops paying from it and sweeps wait | the cold ceremony `set-destination` (hours) and the zone config edit `sweep_destination` with a restart: sweeps wait until both are done, nothing is lost |
| **EVM deposit keys** | none exist: forwarders pay the factory destination | the same ceremony; the guardian `freeze()` stops sweeping at once |
| **Bitcoin hot shard** | replaced with the deposit tree (it is a child of the same account key): `-compromised` on the tree, then the drain consolidates the hot outputs into the successor's shard | DKG of the new 2-party tree; customer notice |
| **Bitcoin deposit keys** | new addresses come from the new generation at once; old addresses stay watched, swept to the new hot shard | none; the sweep of each old address needs the 2 parties |
| **Solana hot shard** | `qv-rekey emergency` (K4 on K8): the record stops ordinary signing, allows only the drain to the successor (tokens, the SOL, the old pool's accounts), lifts the hourly rate; the drain does not wait for the new pool and moves the SOL before the pool's accounts; core stops paying from it | the new pool afterwards (`qv-sol-nonces -generation N`), the cold ceremony for deposits, the zone config edit; tokens are not ordered by value (backlog); the Solana emergency has been run on a local validator only |
| **Solana deposit keys** | like Bitcoin deposit keys | none |
| Cold key, admin keys | not this page: "If the cold key is in doubt" below, and the key-ceremony pages | |

### Work in flight at the mark (Solana)

A transaction of the stolen key that the zone refused before any signature is released by the core at once (its nonce account is given back unused: a sweep fails and is planned again, a withdrawal is voided and its hold released) and does not hold the drain. A refusal by a cosigner after the gateway reserved is released too: the stolen key cannot cancel, and its drain takes the account's lamports whatever claims it (tested: the zone signs the drain's withdrawal of a claimed nonce account).

**What can still hold the drain:** a transaction that may be signed (one of its sign jobs is done or failed, so a signature may exist). A message signed on a durable nonce can land at any time until the nonce advances or the nonce account is withdrawn. The core keeps its nonce account allocated; the stolen key cannot sign the cancel, so the owner is parked (`failure_reason` starts with `parked: the gateway refused to cancel the nonce`, with an ALERT in the worker log) and the drain shows `waiting: N transactions built from the old address are still in flight; the drain starts when they are final`. That text does not name the owner: find it with `SELECT owner_kind, owner_id, address, status FROM sol_nonce_allocations WHERE hot_address='<old address>' AND status IN ('allocated','broadcast')`.

Two ways out, and what exists today:
1. **The payment should happen:** the signed message is broadcast and confirms, the allocation closes and the drain goes on. There is **no operator command** to broadcast a parked owner's signed message; it is backlog.
2. **The payment is abandoned:** once the drain withdraws the nonce account the message can never land, and the owner should then be voided with its hold released. There is **no operator command** to declare a parked owner abandoned (which would release the allocation so the drain may take the account); it is backlog. Until one exists this needs a reviewed change in the database by the core's operators.

## Decide: who and on what evidence (two minutes)

- **Any one operator or the on-call person may stop signing paths** (step 1 and 2 below): stopping is cheap and reversible.
- **The record needs `min_operators` distinct operators (the default is two).** Two is right for an emergency: the record can only stop signing for one generation and
  let it move funds to a successor that is already registered; it cannot send money anywhere else, so a second signature costs minutes and prevents a single
  person from taking a key out of service by mistake or by force. Do not lower it for emergencies.
- Evidence that is enough: a `nonce consumed` ALERT for a transaction we did not make; an outgoing transaction from the hot address with no withdrawal; Reconcile
  showing a difference at the hot address; a leaked file or a lost host that held the key; a published flaw in the signing library. When in doubt, mark: a marked key
  that was not stolen costs a replacement; an unmarked stolen key costs the balance.

## Prepare (before an incident)

| What | Why |
|---|---|
| **A standing candidate per hot shard** (recommended): make the next key now (`qv-rekey open`, `dkg`, `candidate`), leave it a `candidate` (it signs nothing). The emergency run adopts it, so no DKG or token key has to be made while the thief races | saves the longest step: a DKG on three parties or a key in the token takes minutes and needs the parties healthy. Cost: one more key on the parties or in the token, and a candidate to re-check once a quarter (the drill does) |
| Guardian key online, one per chain (`qv-guardian`) | `freeze()` stops all sweeping of the chain at once |
| Cold key custodians reachable (M of N) and the offline config with the **pinned `new_destinations`** including the candidate's address | the destination ceremony cannot be improvised |
| Operators' keys on two people's machines; `qv-keysets` and `qv-rekey` installed there; the shard's work directory | the record is signed offline; it is valid for 10 minutes after signing (`max_change_age`), so it cannot be signed in advance |
| Cold address funded with gas | for the ceremony fees (`POST /v2/cold/fundings`) |
| Alerts on (below) | you learn of a stall from the pager |

## The procedure

Times are from the drill on the local test chains (`TestEmergencyDrillStolenHotKey`); real chains add block times, parties and people.

| # | Who | Step | Time |
|---|---|---|---|
| 1 | on-call | **Freeze the factory** (EVM): `qv-guardian freeze -rpc … -factory … -key-file guardian.key -core http://…`. Sweeps of the whole chain stop; deposits stay in their forwarders, safe | one transaction |
| 2 | on-call | **Stop the stolen key's paths we control** only if the zone cannot be reached (it normally can): stop the gateway for that partition and the withdrawal workflow. Skip this when the record can be signed within minutes: the record does it better | seconds |
| 3 | two operators | **Sign the emergency record and run the driver.** On the operators' machine: `qv-rekey emergency -dir D -config zone.json -guard-dsn … -core … -token-file … -shard S -mode hsm\|mpc -reason "…" -cap ASSET=N …` (one run per shard, at the same time for several). It adopts the standing candidate, or makes a key if there is none (then it needs `-admin-auth` for mpc), prints `qv-keysets sign … -seq N` lines for `register-candidate` (only if the candidate is not registered), `mark-compromised` (successor and caps in it) and `activate`; the two operators sign each (`-join` adds the second signature), then run the same command again with `-changes FILE` for each file. A kill at any point: run it again | candidate adopted: about as long as the people take to sign; no candidate: plus the DKG |
| 4 | (automatic) | **The zone's next decision refuses the old key** for anything but its drain; the core stops paying from it and stops sweeping into it; the planner drains the most valuable asset first (price table `price_wei`), the native asset in its place once gas for the rest is set aside; shards drain at the same time | one poll, then one transfer per asset |
| 5 | operators (M of N) | **Cold ceremony: `set-destination` to the new hot address** (`POST /v2/cold/actions`, `qv-cold inspect/approve/sign`), then the zone config `sweep_destination` and a restart of the gateway and cosigners. This also unfreezes the factory | hours; sweeps wait meanwhile |
| 6 | on-call | **Watch** `emergency.log` in the work directory (it prints every change with the time since the start), `GET /v2/reconcile`, the old address on a block explorer | |

If the run says `STALLED`, read the reason on the line: gas missing at the old address (send a little native asset to it: it is the thief's key, so only what the drain needs), a zone database that is behind (`qv-keysets show`; apply the same record again), or the cap (a signed `set-drain-caps` raises it: `qv-rekey caps`). Then run the command again.

## Work in flight at the mark (EVM)

A withdrawal or a sweep built a moment before the mark may be in any state. The drain starts only when nothing from the old address can still reach the chain, and the run says what it waits for: `waiting: N transactions built from the old address are still in flight; the drain starts when they are final: withdrawal wd-… at nonce 7 is broadcast (sign jobs: …)`.

| State at the mark | What the system does | What you see |
|---|---|---|
| built, or queued for signing | the core rejects the queued job at once; the withdrawal is voided (its hold is released), the sweep fails | nothing waits |
| being signed | the zone answers at its next decision: refused, as above; signed, as the next two rows | a wait of seconds |
| refused, no signature (the zone refuses the cancel too: a compromised key signs only its drain) | the nonce becomes a hole; the next drain transfer uses it, so the nonce lane stays gapless | nothing waits |
| refused after the gateway claimed the nonce (a cosigner that already had the mark refused: `signer_refused`) | the core asks for the cancel; the zone signs a compromised key's own cancel of a nonce it claimed (zero value, to itself, within `max_cancels_per_source`, default 16, once the successor is active); the cancel fills the nonce and the drain goes on | the sweep or withdrawal ends cancelled; a short wait until the activation |
| signed, not broadcast | the worker broadcasts it; the drain waits for it to confirm | the wait names it |
| broadcast, not confirmed | real: it can still mine, so the drain waits. The old key cannot sign a fee bump (the zone refuses it), so it confirms at the fee it has | the wait names it and its nonce |

Sweeps are not planned while the sweep destination is the compromised address (until step 5 is done); funds that arrive meanwhile wait in the forwarders. A sweep that confirms after the mark puts funds on the old address: the drain looks at the balance again when every transaction is final, and the driver checks twice before it says `drained`.

**Rollout.** The gateway and every cosigner must run the version that signs this cancel. A cosigner on the old binary refuses it (the failure is safe: the old residual returns, the nonce stays claimed and the drain of that address stays blocked, with `policy`/`keyset_state` refusals of the cancel in the gateway log): upgrade them together before relying on it. Start the upgraded gateway and cosigners **before** you run `qv-rekey`, `qv-keysets`, `qv-approvers`, `qv-route` or `qv-fee-caps` against the zone: the services bring the guard database to the new schema when they start, and a tool finds it current and runs no schema statement (an older tool or an old database would run them once, with table locks, while the zone is deciding).

The cancel waits up to a day for the successor to become active in every guard (an emergency run paused longer than that is resumed by clearing the parked row: the next attempt is a new cancel with a new deadline, made only when the first was refused as expired before the zone reserved anything and nothing of the owner can have been signed). A compromised key's cancels are counted from the mark, up to `max_cancels_per_source` (16); routine cancels from before the mark and the hourly cancel rate do not use that allowance up.

**If the wait does not end** (`STALLED` names the transaction): read the sign jobs on the line.
1. A job `failed` or `signing` for longer than a few minutes: the signer had a fault, not a refusal. Fix the signer (gateway and cosigner logs); the job completes or is rejected, and the wait ends. Never mark it rejected by hand: a signature may exist.
2. Broadcast and not confirming for a long time: look at the transaction on the node. It is real, so the drain does not start under it (it would spend the balance the transaction needs and queue behind its nonce). The system has no way to replace it, because the old key may not sign a fee bump. It mines when the fee allows. If the node dropped it, nothing replaces it (the replacement would be signed by the old key too): the decision to go on without it is a human one, and no tool makes it for you (backlog: a drain transfer that replaces it at the same nonce).
3. A row is `parked` (an `ALERT` named it): read its reason, fix the cause, clear the parked reason as the other runbooks describe, and run the command again.

## Work in flight at the mark (Bitcoin)

The signing gateway claims every coin a payment spends before the parties sign. When a cosigner that already has the mark refuses the payment (`signer_refused: ... is compromised`) no signature exists but the claim stays, and a drain move that spends that coin is refused `replay_nonce_taken`. Before this rule one such coin stopped every move behind it: the whole shard stayed at the old key.

| State at the mark | What the system does | What you see |
|---|---|---|
| refused by a rule, before anything was claimed | the coins are released; the withdrawal is voided | nothing waits |
| refused by a cosigner after the gateway claimed the coins (`signer_refused`) | the coins are **not** released. The core asks for the cancel; the zone signs a compromised generation's strict cancel (exactly the claimed coins, one output back to the same generation's hot shard, within the fee cap and `max_cancels_per_source`, default 16 for each compromised generation, once the successor is active). When it confirms, the payment ends cancelled (hold released, fee booked) and the output is an ordinary coin that the next drain move takes. The drain does not wait: every other coin moves at once | the drain state says `N coins held by a refused payment: cancel pending / cancel signed, waiting for confirmation` |
| signed, broadcast | real: it confirms, or the cancel replaces it (the chain mines one of the two; the books follow whichever confirms: paid, or voided with the hold released) | the withdrawal's own status |
| a drain refused `replay_nonce_taken` for a coin the core did not know was claimed (a refused CPFP child, or a payment the core had already released) | the coin is held out of the drain moves (reserved, owner `claimed`) and the other coins move on | `N coins held by a payment the zone says it claimed ... an operator must cancel it` |

No tool cancels a held `claimed` coin yet (backlog): it needs the strict cancel of the intent named in the state text, signed through the zone, and engineering to release the reservation afterwards. Do not release it before that cancel confirms: a drain would be refused again.

**Rollout.** Gateway and every cosigner together, as for EVM. A cosigner on the old binary refuses the cancel (safe: the old residual returns).

## Verify

- `qv-rekey status` shows the old generation `compromised`, drain `drained`; Reconcile is clean.
- The old address holds only dust (explorer). A withdrawal made now leaves from the new address.
- Metrics: `qv_keyset_compromised` is set for the generation and `qv_emergency_drain_stalled_seconds` is 0.
- Deposits made after step 5 are swept to the new address.

## Afterwards

1. **Rotate what else the thief may have seen:** the guardian key (ceremony `set-guardian`) if its host is in doubt; the parties' admin keys and the operators' and approvers' keys if the host that held the old key also held them; HSM PINs; the zone and business database credentials of that host.
2. **Audit trail:** `qv-keysets show`, the audit chain (`keyset.compromised`, `drain.*`), `emergency.log`, the chain history of the old address against the ledger: what was signed in the window and by whom. Keep the old key's shares, token key and backups: they are evidence. **Never retire a compromised generation** (the zone and the tool refuse); it stays in the watch list for good.
3. **Customers:** Bitcoin and Solana: new addresses are issued from the new generation at once; old ones stay watched and swept; tell customers to use the new ones.
4. **Next standing candidate:** make the next candidate for the new generation.
5. **Post-mortem** within a week, and a drill after any change to the path.

## If the guardian key is the one that leaked

It can freeze and nothing else, so the damage is a denial of sweeping. Rotate it with the ceremony `set-guardian` (the new address must be in the offline
config's `new_guardians`). Until then any freeze is undone by `set-destination`.

## If the cold key is in doubt

Move the admin role to another cold key: ceremony `transfer-admin` (the new address pinned in `new_admins`), then **the new key** runs `accept-admin` from its own offline machine. After
that the old key's calls revert on chain. Then update the cold address in the signing-zone config and the business config. This is the slowest path; practise it.

## Alerts

| Alert | Metric | When |
|---|---|---|
| A generation is compromised | `qv_keyset_compromised` (core metrics port) | any series: page, until the post-mortem closes it |
| The emergency drain stalled | `qv_emergency_drain_stalled_seconds` | above 600 for 5 minutes: page |
| The emergency metrics cannot be read | `qv_emergency_metrics_error` | 1 for 5 minutes: page |
| Zone refused drains | `qv_drain_refusals_total` | see [key-replacement](key-replacement.md) |

## Drill

Once a quarter and after every change to this path, on the test chains: `make test-e2e-all GROUPS=e2e-evm-drill` runs `TestEmergencyDrillStolenHotKey` (a withdrawal in flight, a refused sweep and withdrawal stranded at the mark, and
deposits arriving, the three records signed, the driver run killed and rerun, the old key's transactions refused, funds ending at the new key, the ledger clean). It logs the time of every step. Run the cold ceremony part by hand with a spare address ([key ceremony](key-ceremony.md)): `TestFactoryAdminRotationCeremony` and `TestGuardianFreezeAndCeremonyUnfreeze` cover it against anvil.

A key ceremony (new keyset, refresh, unfreeze) is done with `qv-party-admin`: [key-ceremony.md](key-ceremony.md).
