# Key replacement: keysets and drains (incomplete)

> **Incomplete.** This page covers the signing zone's own keyset states, the business side (the admin routes and what the core does with two generations of one shard), and the drain, for **EVM hot shards**. The DKG and self-test of a new key and the one tool that runs every step (`qv-rekey`, K3), and Bitcoin and Solana, are not built yet. Do not use it as a full replacement procedure.

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
4. **Drain** (planned by the core later): an intent of kind `drain`, with the shard's partition, the asset, `from` the old address, `to` the successor's address. It needs no approval and no requester.
5. **Retire:** `-action retire -shard S -generation 1`. The zone cannot see the balance; confirm on chain first.

**Compromise:** `-action mark-compromised`. It may name `-successor` and `-cap` in the same record (once). A compromised key signs only a drain to that successor.

## What the zone checks and what it cannot
The zone signs a drain only from a `draining` or `compromised` generation to exactly the successor's address, as a plain transfer (native: no data; token: `transfer(successor, amount)`), within the signed cap and `drains_per_hour` of the chain config (default 10; 0 turns drains off). It **cannot** check that the amount is everything: it has no chain access. A smaller drain is harmless; the rest stays on the old key until drained again. To raise a cap there is no action yet (planned with K2b/K8).

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
| 4 | the drain (next section) | the core plans it by itself |
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
