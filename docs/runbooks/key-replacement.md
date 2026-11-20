# Key replacement: replacing an EVM or Solana hot shard's key, and the deposit keys of Bitcoin and Solana

This page is the procedure for **EVM hot shards**, run with `qv-rekey`, in the planned and in the emergency order. **Solana hot shards** follow the same steps with the differences in [their section](#solana-hot-shards-k4), and the deposit key trees of Bitcoin and Solana have [theirs](#deposit-keys-of-bitcoin-and-solana-k6). The sections after the procedure explain what the zone checks, the business side, and the drain.

## The procedure with `qv-rekey`

`qv-rekey` in `-mode hsm` opens the shard's token with the PIN from the file named by `QV_HSM_PIN_FILE` (mode 0400, or 0440 for a Secret volume), like `qv-gateway`; the environment form `QV_HSM_PIN` is accepted only when `QV_ENV` is `dev` or `test`, and refused otherwise.

`qv-rekey` walks one replacement and **signs nothing**. Operators sign the zone's records on their own machines with `qv-keysets sign` and give the tool the files; the tool applies each file to every zone guard database and then asks the core's admin route to mirror the step. It keeps only `plan.json` in its `-dir`; where a step stands is read from the zone and the core each time, so you can stop at any step and run the same command again. A step already done is skipped. It refuses to go on when the zone and the core disagree and says which side is behind.

Common flags: `-dir WORK` `-config zone.json` `-guard-dsn gateway=… -guard-dsn cosigner-b=… -guard-dsn cosigner-c=…` (every guard database), `-core https://…` `-core-ca ca.pem` `-token-file F` (an admin's token from a fresh login; the routes need step-up and a human). Run it in the signing zone (it needs the guard databases and, for `dkg`, the parties or the token).

| Step | Command | What happens | Needs |
|---|---|---|---|
| 1 | `open -shard S -mode mpc\|hsm -reason "…"` | checks the shard has one active generation, none in flight, and the zone and core agree; writes the plan (old generation, new generation) | nothing |
| 2 | `dkg` | **mpc:** a 2-of-3 ECDSA DKG on the three parties (keyset `<shard>-g<N>`); **hsm:** a new key in the shard's token, test-signed. The plan keeps the key reference, public key and address. Run again: it finds the key, makes no second one. Checks that the parties agree on the key | mpc: an operator's `qv-keysets party-auth -key admin.key -op dkg -keyset ID -out auth.json` made just before (valid for minutes, once) and given as `-admin-auth` |
| 3 | `candidate` | prints the `qv-keysets sign … -action register-candidate -address … -key-ref … -public-key …` command and its sequence number. With `-change FILE`: applies it to the zone, then `POST candidates` to the core. The record carries the key reference and public key, so the zone can sign from the new key later; a candidate signs nothing | two operators sign (`-join` adds the second) |
| 4 | `drain-start -cap ASSET=N …` | same pattern with `start-draining` (successor = the new generation). **Emergency:** add `-compromised` (the record is `mark-compromised`, successor and caps in the same record). The caps are the most **all** signed drains of an asset from the old key may move: the zone cannot read the chain. Give them room (a few times the balance) | two operators |
| 5 | `activate` | `activate` in the zone, then the core. **The shard has no active key between 4 and 5: new withdrawals wait, so run 5 at once.** Prints the cold ceremony and, with `-rpc` and `-factory`, whether the factory already pays the new address | two operators |
| – | **Cold ceremony** (human, outside the tool) | see below | M of N custodians |
| 6 | (automatic) | the core's drain planner moves each token, then the native asset, from the old key to the new one; `status` shows `drain moving / waiting / drained` | – |
| – | `caps -cap ASSET=N` | if the zone refuses a drain because the cap is spent (`policy_drain_cap`), raise it: signed `set-drain-caps` record (the new **total** for that asset, counting what was drained already). Zone only | two operators |
| 7 | `retire` | refuses until the core says the drain is `drained`; then `retire` in the zone, then the core (which reads the chain again and writes off the dust). Not for a compromised key: it is never retired | two operators |
| – | `status` | zone databases (with their sequence numbers), the core, the drain, the next step, and whether the factory points at the new address. Exits with an error on a disagreement | – |

**The cold ceremony** (after `activate`, before sweeps resume): (1) `POST /v2/cold/actions {"kind":"set-destination","param":"<new address>"}`, then `qv-cold inspect/approve/sign/import` (read: destination old → new); (2) in the gateway's and every cosigner's config, and the business config where it is set, change `sweep_destination` to the new address and **restart the gateway and the cosigners** (the zone refuses to sweep to a generation that is not active, and to any address but its configured one). Until both are done sweeps wait ("factory destination differs", an `ALERT`); nothing is lost. The tool prints these lines and, with `-rpc/-factory`, checks the factory.

**Planned order:** 1, 2, 3 at leisure (nothing moves, the old key keeps working); then 4 and 5 together; the ceremony; wait for `drained`; 7. The old key's backups and shares are kept until the watch window ends (nothing in the tool destroys them).

**Emergency order** (the hot key may be stolen; [stolen-hot-key](stolen-hot-key.md) has the first minutes: freeze the factory, stop the key's signing path): 1, 2, 3 as fast as the people allow; 4 with `-compromised` (the old key now signs **only** its drain to the new key, within the caps; the attacker's own copy of the key is not affected, so the window until this record is lost money, bounded by the hot balance and the caps); 5; the ceremony (it is also the unfreeze); the drain empties the old key; the old key is **never retired**, it stays in the watch list and its shares are kept for the investigation.

## What a drain can and cannot do to the zone's allowance
The zone counts, against `drains_per_hour` and against the signed cap, the drains it **signed** (and those being signed right now, for the sign timeout). A drain the zone refused, that a cosigner refused, or that expired unsigned counts for nothing, so a retrying planner cannot use up the allowance. Refusals are counted and raise `ALERT drain refused` with the reason, so a storm is visible. The cosigner never stores a signature (party A does), so it counts what it authorised.
- *Before:* a business zone (or a broken planner) that asked for drains the zone then refused or let expire could fill the hourly limit and the cap (an expired drain of 110 ETH nine times filled a 1000 ETH cap); the real drain then could not be signed, and the only remedy was a new `start-draining` record, which does not exist for a draining key.
- *After:* only signed drains count; to move more than the cap a signed `set-drain-caps` from the operators is needed, which the business zone cannot make. What the business zone can still do is ask for drains the zone signs (to the successor, within the cap): at worst it moves the old key's money to the new key sooner than planned.

## Signing from the new generation
The zone resolves the key of a job from the **sender's address**: generation 1 is the key the config's `signers` section pins; a later generation is the key named by the record that registered it (key reference and public key, which must hash to the address). The config says how to reach a key (the token, or the parties and their certificates); the record says which. A later generation signs only as its state allows (table below); policy counters (daily caps, rates) are per chain and asset, not per generation, so a replacement does not double an allowance. The cosigners run the same decision from their own records, so each refuses independently. A candidate registered **without** a key reference can receive but not sign: the zone raises `ALERT keyset registry: the zone cannot sign from a generation…`.

**Rolling update:** upgrade every gateway and cosigner before starting a replacement: an older binary does not know the new record fields (it ignores such a record: `ALERT … rows … are ignored`) nor the `drain` kind. The guard database gets two columns (`key_ref`, `public_key`) when the new binary starts; records written before are unchanged and still verify.


## What the zone checks
The zone decides from its own records, not from the business side. Each hot shard has generations of keys; a pinned hot address in the zone config is generation 1, `active`. Operators (the same key set as in [approvers](approvers.md), `min_operators` of them) change a generation's state with `qv-keysets`.

| State | What the zone signs from it |
|---|---|
| `candidate` | nothing |
| `active` | what an active key signs |
| `draining` | only a drain to its successor, and the replacement or cancel of work it already signed |
| `retired` | nothing |
| `compromised` | nothing, except a drain to its successor |

A sweep, rebalance or forwarder destination must be an `active` address. A shard has one `active` generation.

## Steps
All changes use `qv-keysets sign` (each operator, on their own machine; `-join` adds a signature) and `qv-keysets apply -config zone.json -guard-dsn gateway=… -guard-dsn cosigner-b=… change.json` (every guard database). `qv-keysets show` lists generations, states and the sequence number. The shard ID is `entity/chain/pool/number`, not a partition ID.

1. **Register the candidate:** `-action register-candidate -shard S -generation 2 -address 0x…`. The new generation is the next number; its address must be new.
2. **Start the drain:** `-action start-draining -shard S -generation 1 -successor 2 -cap ETH=<base units> -cap USDT=<base units>`. The caps are the most **all** drains of that asset from this key may move, chosen by the operators who know the balance. They are in the signed record so that the zone, which cannot read the chain, has a bound it trusts. An asset with no cap cannot be drained. A generation that others still drain into cannot start draining.
3. **Activate the successor:** `-action activate -shard S -generation 2`. A drain is signed only once the successor is `active`.
4. **Drain** (planned by the core): an intent of kind `drain`, with the shard's partition, the asset, `from` the old address, `to` the successor's address. It needs no approval and no requester.
5. **Retire:** `-action retire -shard S -generation 1`. The zone cannot see the balance; confirm on chain first.

**Compromise:** `-action mark-compromised`. It may name `-successor` and `-cap` in the same record (once). A compromised key signs only a drain to that successor.

## What the zone checks and what it cannot
The zone signs a drain only from a `draining` or `compromised` generation to exactly the successor's address, as a plain transfer (native: no data; token: `transfer(successor, amount)`), within the signed cap and `drains_per_hour` of the chain config (default 10; 0 turns drains off; **not applied to a compromised source**), and at most `max_drains_per_source` drains signed from one address in all (default 40, every state; on Solana 40 plus the pool size and the number of tokens, see [Solana](#solana-hot-shards-k4)): the cap counts value, each drain also costs gas, so this count bounds the gas a storm of tiny drains could burn. It **cannot** check that the amount is everything: it has no chain access. A smaller drain is harmless; the rest stays on the old key until drained again.  A cap is raised with a signed `set-drain-caps` record (`qv-keysets sign -action set-drain-caps -generation G -cap ASSET=BASE_UNITS`): a draining or compromised generation, the new total per named asset.

## Deposit keys of Bitcoin and Solana (K6)
The deposit key tree of such a chain is the registry entry `entity/chain/deposit-tree/0` in both sides (the zone's signed log, the core's `keysets` table). Generation 1 is the key the configs pin; every later generation exists because two operators signed it. Its identity is the account xpub (Bitcoin) or the Solana node `<public key hex>:<chain code hex>`; its key reference is the ID of a **second 2-party HD keyset on parties A and B** (curve secp256k1 or ed25519). Each `deposit_addresses` row carries its `generation`; "get my deposit address" returns the active generation's address and lists the older watched ones in `older_addresses`; a sweep's sign job names the key as `g<N>/<path>` from generation 2 (generation 1 is unchanged).

**What a generation is on each chain**
- **Bitcoin**: one generation is one account key, so it is the deposit addresses (branch 0) *and* the hot shards (branch 1, the same partition under that key). Replacing it replaces both: new work (withdrawals, batches, moves to cold, consolidations, sweeps) is built from the active generation's hot shard; the old hot shard is *drained* into the new one.
- **Solana**: only the deposit node is replaced here. The hot shard and its nonce pools are the hot-shard replacement (K4); a sweep of any generation that is active, draining or compromised pays the partition's pinned hot shard.

**States in the zone** (rules per generation; all existing fee, batching, cancel and first-send rules hold unchanged for each)
| State | Bitcoin | Solana |
|---|---|---|
| candidate | signs nothing | signs nothing |
| active | everything as before; a sweep of its addresses pays *its* hot shard | sweeps as before |
| draining | sweeps of its addresses, only to the successor's hot shard (the successor must be active); a `drain` of its hot shard to the successor's, within the signed cap; cancels and replacements of work it already signed. No withdrawal | sweeps of its addresses |
| compromised | as draining, except cancels and replacements | sweeps of its addresses |
| retired | signs nothing | signs nothing |

The generation an input is under is read from the zone's own derivation: the payload says which one it claims, and the zone derives the script from the account key *its own signed record* gives for that generation (an unknown generation is refused). The gateway and each cosigner judge independently from their own log.

**The flow** (same tool and same ceremony as an EVM shard; `-shard` is the tree ID)
```
qv-rekey open        -shard qv-us/btc-main/deposit-tree/0 -mode mpc -reason "..."
qv-rekey dkg         -admin-auth F          # a second HD keyset on the parties; F from `qv-keysets party-auth -op dkg -keyset <printed ID>`
qv-rekey candidate   [-change F]            # zone record: -key-ref <keyset ID> -public-key <xpub | node>, no -address
qv-rekey drain-start -cap BTC=SATS -window SECONDS [-change F]     # Solana: no -cap. The window is signed: the old generation may retire only after it
qv-rekey activate    [-change F]            # new customers get generation 2 addresses; sweeps of old addresses now pay the new hot shard
qv-rekey status
qv-rekey retire      [-change F]            # refused inside the window and while anything of the generation holds more than dust
```
Run every zone step first (the tool applies the signed file to the gateway's and every cosigner's guard database, then mirrors the step in the core); the tool refuses to go on when the two disagree. Between `drain-start` and `activate` the chain has no active generation: withdrawals wait (like an EVM shard) and sweeps are refused and retried; run `activate` right after.

**The drain of the Bitcoin hot shard** is the consolidation's shape: the partition's outputs under the old key (at most `max_inputs` a transaction, the oldest first, outputs that cost more to spend than they carry are left) go in one output to the same partition's shard under the new key. The planner (the drain loop of the worker) makes the next move when the last is final, and `status` shows `drained` when nothing above dust is left. The fee caps, the fee rate ceiling and fee bumps (RBF, cancel) apply as for any send. The zone signs it only from a draining or compromised generation, to the successor's address, within the signed `-cap BTC=SATS` and `drains_per_hour`; the cap bounds the amount the zone cannot read.

**Old addresses stay watched and swept for the window (decisions D3, D5).** The window is a signed parameter of the `start-draining` record (`-window`, seconds; plan 12 months, not a core setting). The zone refuses a `retire` record signed earlier than `start-draining` time plus the window; the core refuses `retire` while the window has not passed (the tool passes the signed value), while any watched deposit address of the generation holds more than dust or has a sweep in flight, while a drain move is open, and (Bitcoin) while a hot shard under it holds more than dust. A compromised generation is never retired.

**What must be kept for the window, on both parties:** the old keyset (its shares sealed in each party's token or sealer) and every backup of its generation, with the recovery key that opens them, until `retire` is done *and* the window has ended. Sweeping an old address signs with the old key, so a party that loses the old keyset cannot sweep late deposits. Do not destroy anything with this tool; use the parties' own procedure (docs/runbooks/mpc-backup-restore.md) afterwards.

**Telling customers (operational, not code).** After `activate` show the new address on the deposit screen, label old addresses "will be retired on <date>" and mail customers who saved one. We do not control wallets people saved: keep the monthly sweep running and decide late deposits after the window case by case from the retained backups.

**Emergency** (`drain-start -compromised`): freeze first (docs/runbooks/mpc-keyset-freeze.md), then register and activate the new generation and run `drain-start -compromised -cap BTC=SATS` (the old key is marked compromised: it signs only sweeps and drains to the successor and is never retired; there is no window). A stolen key can spend whatever lands on its old addresses, so tell customers at once; the sweeps of those addresses race the thief. Solana: the same, without a cap.

**Alerts.** `ALERT: the signing zone refused the sweep of a deposit address of a later key generation` (core, once per address and process): the zone has no record that lets it sign (generation not registered or not active there, retired), see `status` and `qv-keysets show`. The usual zone alerts for keysets apply (`ALERT keyset registry`, `ALERT drain refused`).

**Rolling update with migration 0032** (K5): it drops the unique index on `(customer_id, chain)` that the previous release names in the EVM address insert (`ON CONFLICT`), so until an old core pod is replaced its "get deposit address" calls for EVM chains fail with a database error. Callers retry and succeed on a new pod; nothing is written wrongly. Upgrade the zone (gateway and every cosigner) before registering a generation: an older binary does not know the deposit tree's records (it ignores them with an ALERT) or the `g<N>/` key references (it refuses the job).

**Kubernetes.** `qv-rekey` runs in the signing cluster as in the EVM flow (guard databases, party A's caller port with the gateway's client certificate); `qv-keysets sign` on operators' own machines; the core calls are outward from the signing zone (or run on a business-zone host: only `-core` needs it). The drain planner is the worker's existing loop; state is the business database (`drain_moves`, `keyset_drains`, `btc_utxos.path`), so a second worker replica or a restart is safe.

Generation 1 never changes: the core refuses to start when the configured key differs from the registered one.

## Solana hot shards (K4)
A Solana hot shard is replaced with the same tool, the same signed records and the same states as an EVM one (`-shard entity/chain/pool/N`, for example `qv-us/sol-main/omnibus/0`). The record carries the **new address in base58**, the **key reference** (the ID of a 2-of-3 Ed25519 keyset on parties A, B and C) and the **32-byte public key in hex**, which must be the address's bytes. `qv-rekey dkg` makes that keyset (`-admin-auth` as for EVM; the shard's signer entry in the zone config is `ed25519-2of3`). What differs is everything the old key owns on Solana.

**The order, and why**
```
qv-rekey open | dkg | candidate | drain-start -cap SOL=N -cap TOKEN=N … | activate     # as for EVM; caps in base units (lamports, token units)
(automatic)   the drain planner moves every configured token, then SOL for the new key's nonce pool, then waits
qv-sol-nonces -config CUSTODY.json -dsn $DATABASE_URL -shard N -approver NAME -approver-key FILE      # the new key's pool, one approval (the active generation)
(automatic)   the old nonce accounts, then the last lamports: the old address ends at zero
qv-rekey status | retire
```
1. **The new key needs a pool of its own** (durable-nonce accounts, authority the new key) before it can pay a withdrawal or a sweep. Creating it needs SOL at the new address, and the books must see where that SOL came from, so it comes from the drain: the first moves are the tokens, then just enough SOL for the pool. A candidate signs nothing, so the pool is created **after** `activate`. Between `activate` and the pool, new withdrawals wait ("no free nonce account", or "successor key not funded yet"); a customer's request is not lost. Keep that window short: run `qv-sol-nonces` as soon as `status` says the drain waits for the pool.
2. **The old pool is emptied after the new one exists.** Each old nonce account is withdrawn into the new address (rent recovered; the books lower the shard's cost by it), one account a move, only when no withdrawal or sweep holds it and the node no longer shows the value its last owner signed.
3. **The last move** sends all SOL but the fee of that transaction (5000 lamports), so the old address holds exactly zero.

**What the drain moves, in order** (each is one transaction on a recent blockhash, paid and signed by the old key alone; one open move per generation):
| Step | What | Zone's shape |
|---|---|---|
| tokens | for each configured token with an account: transfer all of it to the new address's associated account (created, paid by the old key, if missing) and **close the old token account, its rent paid to the new address**; an empty account is only closed | `drain` of the token: transferChecked, optional closeAccount |
| fund | SOL for the new key's pool (rent of each account, fees), once | `drain` of SOL: one system transfer |
| nonce accounts | one old pool account at a time, whole balance to the new address | `drain` of SOL: one WithdrawNonceAccount |
| last SOL | everything left but the fee | `drain` of SOL: one system transfer |

**In-flight work.** A withdrawal or sweep built before the switch keeps the old key and the old pool's nonce: a stuck one is still replaced (fee raise) and cancelled with the old key, because the zone lets a draining key finish exactly the work it signed. The drain starts only when no allocation of the old key is open, so a withdrawal lands once or is cancelled by advancing its nonce, never twice and never stuck. New withdrawals are built from the active key only.

**Dust and what the books do not know.** Less than the fee of the last transaction (5000 lamports) cannot be moved and is written off at `retire`. Tokens of a mint the config does not list, and token accounts that are not the associated one, are **reported** (an `ALERT`, and the drain's reason on `status`) and never moved or burned: `drained` is reached with them still there; decide by hand (a recovery with the old key before the shares are destroyed) before `retire`.

**What the zone checks** (each tested): the fee payer is a generation of the partition's shard and each generation owns its own pool (a nonce of another key's pool is refused); a **candidate** signs nothing; an **active** key signs what a hot shard signs, including the creation of its pool; a **draining** key signs only a `drain` to its successor (the successor active, to the named address, within the signed per-asset cap and `drains_per_hour`), the closing of its own nonce accounts to itself (`nonce-close`, as before), the cancel and replacement of work it signed; a **compromised** key signs **only** the `drain` to its successor, no cancel, no nonce close, no replacement (the rule of EVM); a **retired** key signs nothing. A rebalance pays only an active generation of another shard. Each cosigner judges from its own log.

**Compromised key (emergency).** `drain-start -compromised -cap …`, or `qv-rekey emergency`, as for EVM: the old key signs only its drain to the new one, in every shape of it (a token transfer with its close, the close of an empty token account, a withdrawal of an old pool account to the successor, the SOL), no cancel, no `nonce-close`, no replacement, and the hourly drain limit is not applied (tested in the gateway and in the e2e). The drain differs from the planned one in two ways, because a thief races it: it does **not** wait for the new key's pool (the operator creates the pool afterwards, `qv-sol-nonces -generation N`, from the SOL the drain brought), and the SOL goes before the old pool's accounts (all but the fee of every transaction still to come). Tokens still go first, in the order of the asset list: the Solana planner does not order them by value (backlog). Freeze the old keyset on the parties first (mpc-keyset-freeze.md). The old key is never retired.

**How many drains one key may sign.** `max_drains_per_source` (K8) bounds the drains signed from one address in all, to bound the gas. Every step of a Solana drain is one drain: a token (transfer and close, or only the close of an empty account), a pool account, the SOL, and a retry after a failed one. So the default on Solana is 40 + the pool size + the number of configured tokens + 1 (up to 40 + 64 + tokens + 1), not 40; a value in the config is taken as it is, so set it to at least pool + tokens + retries. Each step costs one base fee (5000 lamports), so the gas the bound allows stays small. Worst case by count: the e2e (pool 3, one token) 5 steps; a wallet with 20 tokens and a pool of 16 needs 37, and one with 30 tokens and a pool of 32 needs 63, which the 40 of other chains would have refused halfway.

**Sweeps and Reconcile.** Sweeps of deposit addresses pay the active generation's address after `activate` (the zone refuses a sweep that pays a draining one). Reconcile adds up every generation that is not retired as one shard, explains a drain transaction that is final and not booked yet from its own record, and books each move's cost (fee, less rent that came back) when it settles. Nothing is booked for the amount: it stays in the shard.

**Crash safety.** Every step is derived from the chain at finalized commitment and from the registry, never from memory: kill `qv-rekey` or the worker between any two steps and run it again. A drain move and its sign job are written in one transaction; the signature is recorded before the send and the send repeats while the blockhash is valid; a move whose blockhash expired unconfirmed ends as failed (nothing moved) and the planner builds the next one from the chain.

**Signer mode.** The Solana hot shard is an MPC keyset on the three parties today (there is no HSM mode for Solana), so only the MPC path of `qv-rekey` applies. `qv-keysets sign`'s help text speaks of secp256k1 keys: for Solana `-address` is the base58 address and `-public-key` the 32-byte key in hex.

**Kubernetes.** `qv-rekey` runs as for EVM: a Job (or `kubectl exec`) in the signing cluster with the guard databases, the zone config, party A's caller port and the gateway's client certificate mounted, `-core` reaching the business zone's admin API outward (or run those calls from a business-zone host). `qv-keysets sign` stays on operators' machines. `qv-sol-nonces` runs where the business database and the signing zone's job queue are reachable: a Job in the business cluster with the custody config and the approver key mounted as secrets (one approval, then discard). The drain is the worker's existing drain planner loop, so nothing new runs, no new port opens and no chart value changes; the gateway and every cosigner must run this release first (an older zone ignores the new records with an ALERT and refuses the key references).

## Differing databases and rolling updates
The gateway and each cosigner judge by their own verified log. A drain whose state does not hold in one of them yet (source not draining, successor not active) is **not refused**: it waits with an `ALERT keyset registry: a drain waits…` until its `not_after`. Run `apply` again to finish; `show` warns when sequence numbers differ.

During a rolling update, a replica on the old binary does not know the kind `drain` and **refuses** it normally (`intent kind`, no crash). Upgrade every gateway and cosigner replica before starting a drain.

## On Kubernetes
`qv-keysets apply` needs network access to each guard database and the zone config. Run it as a Job (or `kubectl exec` into a pod with the binary) in the cluster of the gateway and in each cosigner's cluster, with the same files. Every replica of a role shares that role's guard database, so one apply per database is enough, with no restart.

## Alerts
`ALERT keyset registry: rows of the keyset_changes table do not carry valid operator signatures…`: someone wrote to a guard database directly, or the `operators` section changed. The rows are ignored.

## The business side: two generations of one shard
The core keeps its own registry of generations (a mirror, for planning). **The zone decides from its own records, so a wrong mirror can stall work but never move money.** Always do a step in the zone first (`qv-keysets`), then the same step in the core. The routes need an `admin` token with a fresh login, belong to a human (not a service) and are audited with the admin's name.

| Step | Zone (`qv-keysets`) | Core (`/v2/keysets/…`, body: `shard_id`, `generation`) |
|---|---|---|
| 1 | `register-candidate` | `POST candidates` (`shard_id`, `address`, `key_ref`): the address must be new to the deployment; one candidate per shard |
| 2 | `start-draining -successor 2 -cap …` | `POST drains` (`successor`: the candidate) |
| 3 | `activate` | `POST activations` |
| 4 | (the zone signs the drain when asked) | the core plans and runs the drain by itself (next section) |
| 5 | `retire` | `POST retirements`: refused unless the chain shows nothing above dust at the old address and no transaction of it is in flight |
| – | `mark-compromised` | `POST compromises` (`successor` may be named in the same call) |

`GET /v2/keysets` lists every generation with its state, its successor and, for one that is leaving, what the drain last found.

What changes while a shard has two generations:
- **The shard keeps its one ledger account.** New withdrawals, the sweep destination (the active address of the sink shard), rebalance and refill targets use the **active** generation's address. Work already built finishes from the address it was built for, including its replacement or cancel.
- **Between step 2 and step 3 the shard has no active address.** New work for it waits (a withdrawal polls until its deadline, then ends with the reason); do the two steps one after the other.
- **A withdrawal waits until the active address holds what it sends** (and, for a token, the gas), while an older generation still drains into it. Its reason says which address is short.
- **No rebalance or move to cold starts from a shard that is still draining**: part of what the books say it holds is at the old address.
- **The factory.** After step 3 the factory still pays the old address until the cold ceremony `set-destination` names the new one; sweeps stop with "factory destination differs" until it does (they are not lost). Then update the zone's `sweep_destination`.
- **Reconcile** adds up the addresses of the shard's generations that are not retired and compares the sum with the one ledger account; a move between two of them changes neither. A late arrival at a draining address is a difference, and the check names the generation. A retired address is checked on its own: the books expect only the dust written off at retirement; anything more is reported as a late arrival at a retired key (recover it from the backups kept for the window).

**When the core and the zone disagree**
- The core uses generation 2 and the zone still has it as a candidate (or the other way round): the zone refuses the job. A withdrawal ends voided with the zone's reason and its hold is released; a drain waits and is planned again (below).
- A drain whose state holds in one place only waits, as the zone's page says, until the intent's `not_after`; then the core shows the zone's reason on the generation (`drain.reason`) and plans it again. Fix the missing step; nothing is lost.

## The drain, from the core
Once the old generation is `draining` (or `compromised`) in the core and the successor is `active`, the worker's drain planner makes the moves, one at a time per generation: each **token** that has a balance, then the **native asset last**, keeping only what the final transfer's gas needs (a twofold plain transfer at the current fee cap, never more than `max_tx_fee_wei`). Each move is a `drain` job: the shard's partition, `from` the old address, `to` the successor, a short `not_after` (`cold.drain.window`, default 10 minutes). It uses the normal transaction driver (nonce of the **old** address, fee bump, cancel, crash recovery).

- **Books.** The shard's ledger account does not change: a drain moves money between two addresses of one shard. The gas is booked as a cost (fee account to the shard's native account), like any fee.
- **Waits, never a lost place.** `GET /v2/keysets` shows, per leaving generation, `drain.state`: `moving`, `waiting` with the reason, or `drained`. It waits when: the successor is not active in the core; transactions built from the old address are still in flight; the old address has a token but no gas for it; or the zone refused or delayed the move (the zone's own words: not draining or not active **in the zone** yet, the cap, `drains_per_hour`, no `start-draining` record). A refused move ends (its nonce is freed by a cancel) and the planner makes the same move again after `cold.drain.retry_after` (default 1 minute), from what the address holds then.
- **Only signed drains count in the zone** against `drains_per_hour` (default 10) and the cap of the signed record (see above). A refused or expired attempt is free; `ALERT drain refused` shows it. If the cap is spent, raise it with `qv-rekey caps` (or `qv-keysets sign -action set-drain-caps`).
- **Drained.** `drained` means nothing above dust is left. The planner never retires: do `retire` in the zone, then `POST retirements`, which reads the chain again and writes off the dust as a cost. A compromised generation is never retired; it stays in the watch list.
- **Kubernetes.** The planner is one more loop of the worker (`drain-planner:<chain>`); nothing new runs and no new network path is needed. State is in the business database (`drain_moves`, `keyset_drains`); a second worker replica or a restart is safe (one open move per generation is a unique index, the move ID is the workflow ID). A worker older than this release does not run the loop; the migration is additive.

## What is not covered yet
- A cosigner-side self-test of a candidate (a bounded transaction before activation) is not built: `dkg` checks the parties agree on the key (MPC) or test-signs in the token (HSM), and the first withdrawal after `activate` is the first real signature.
- Destroying the old key's shares and backups after the window: do it by the parties' own procedures (docs/runbooks/mpc-backup-restore.md); the tool never destroys anything.

The MPC parties' admin calls (the `dkg` step's signature, refresh, unfreeze) step by step: [key-ceremony.md](key-ceremony.md).
