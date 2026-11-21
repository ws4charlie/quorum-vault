# Key replacement

[中文](zh/key-replacement.md)

A key that someone else may have seen has to be replaced, not just refreshed. QuorumVault makes a new key next to the old one, switches to it, empties the old one into it and then retires it. It is like changing the lock on a safe and carrying the contents across.

<p align="center"><img src="images/key-replacement.png" width="60%" alt="A new key is made and signs nothing. It takes over new payments. The old key moves its funds to the new key and is retired, while its addresses stay watched. In an emergency a stolen key may only move its funds to the new key."></p>

## A refresh is not a replacement

A refresh gives every party new shares of the same key. It helps when someone saw one share and no longer has it. It does not help when someone may hold enough shares to sign, or when the key itself leaked, because the key stays the same. Then the key must be replaced ([MPC signing](mpc.md)).

## Every key has a generation and a state

Each place that holds a key, such as one hot shard, numbers its keys: generation 1, then 2, and so on. The [signing zone](signing-zone.md) decides what a key may do from its state.

| State | What the zone signs from it |
|:---|:---|
| New | Nothing |
| Active | Normal payments |
| Draining | Only a move of everything to its successor, and the completion of work already signed |
| Retired | Nothing |
| Compromised | Only the move to its successor |

Only zone operators change a state. Several of them sign each change, the zone writes it into its own log, and the business side cannot make one.

## Planned and emergency replacement

| | Planned | Emergency |
|:---|:---|:---|
| When | A key reaches the end of its planned life, or people change | A key may be stolen |
| New key | Made and checked at leisure; the old key keeps working | Made as fast as people allow |
| Switch | New payments move to the new key and the drain starts together | The old key is marked compromised at once; from then on it can only move its funds out |
| Old key | Retired once it is empty | Never retired; it stays on the watch list |

In an emergency the thief's own copy of the key is not affected, so the time before the compromised mark is the loss window. One signed record does the whole switch: it stops the old key's normal signing, lets it move funds only to its successor, carries the larger limits for that move, and tells the core to stop paying from it. A tool runs the steps and moves the most valuable assets first. What the thief moves before the move lands cannot be saved; the [stolen hot key runbook](runbooks/stolen-hot-key.md) says so and lists the steps, and a drill plays them.

## The system empties the old key

The core moves each token, then the coin itself, from the old key to the new one. No approver is needed: the zone operators' signatures that started the drain are the approval. The zone signs only a move to the named successor, within a total that the zone operators set in the same record, and counts only the moves it actually signed. A refused move costs nothing, so a broken planner cannot use up the allowance. One tool walks the whole replacement but signs nothing itself ([runbook](runbooks/key-replacement.md)).

## What a customer sees

On EVM chains, nothing: a deposit address is a forwarder that asks the factory where to send, so the address stays the same. On Bitcoin and Solana a deposit address comes from the key itself, so a new key means new addresses, and the customer gets one address per generation. After the new key takes over, the old addresses stay watched for a stated period, and what lands on them is swept into the new hot wallet, signed with the old key. The zone refuses to retire the old key inside that period, and the core refuses while anything is left on those addresses. On Bitcoin the hot wallet uses the same key, so it is replaced and emptied the same way ([Bitcoin](bitcoin.md), [Solana](solana.md)).

A Solana hot wallet is replaced the same way, with two differences. The old key also owns a small pool of nonce accounts, so the drain empties those too and the new key needs a pool of its own before it can pay anyone. And the last move leaves the old address at exactly zero. In an emergency the drain does not wait for the new key's nonce pool, which an operator builds afterwards, and it moves SOL first and then the accounts of the old pool; every step counts as one move, so a Solana drain is allowed more moves than on other chains.
