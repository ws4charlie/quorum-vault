# Key replacement: keysets and drains (incomplete)

> **Incomplete.** This page covers only what exists today: the signing zone's own keyset states and the zone side of a drain, for **EVM hot shards**. Planning a drain from the core (K2b), the DKG and self-test of a new key (K3), and Bitcoin and Solana are not built yet. Do not use it as a full replacement procedure.

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
