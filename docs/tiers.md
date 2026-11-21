# Hot and cold

[中文](zh/tiers.md)

A hot wallet signs all day, so it holds only what the day needs. The rest sits in cold storage, whose key is kept offline. Think of a shop's till and its safe.

<p align="center"><img src="images/tiers.png" width="60%" alt="Above its upper limit a hot wallet moves the excess to cold automatically. Below its lower limit it asks for a refill, which people carry across an air gap."></p>

## Limits decide when to move

Each hot wallet has a lower limit, an upper limit and a target.

| Hot balance | What the system does |
|:---|:---|
| Above the upper limit | Moves the excess to cold storage, down to the target |
| Between the limits | Nothing |
| Below the lower limit | Raises one alert and opens a refill request |

## Hot to cold needs no approval

The cold address is fixed in the signing zone's own settings, which the business side cannot change. A move to cold can only send coins somewhere safer, so even a hijacked core cannot use it to send "cold" money elsewhere.

## A hot wallet can change its key

A hot wallet can switch to a new key without starting new books: new payments leave from the new key, the old key moves everything it holds to the new one, and only then is it retired ([Key replacement](key-replacement.md)).

## A cold key can change too
A cold key is replaced by a ceremony of its own: the old key, signed by M of N custodians, moves everything to a new address that is written into the offline machine's own config, never taken from the request. New hot-to-cold moves go to the new address from the switch, and the old address stays in the books' checks until it is empty ([runbook](runbooks/cold-key-replacement.md)).

## Cold to hot needs people

A refill exposes coins to more risk, so it goes through a key ceremony.

1. The core opens a refill request. Only one request can be open per cold address (on Solana, one per asset).
2. An operator exports it as a file that carries the current nonce and fees.
3. The file is carried across the air gap to the offline signing machine.
4. M of N cold signers approve, and only then does the HSM sign. What may be signed depends only on the offline machine's own settings.
5. The signed file is carried back, checked against the request and broadcast.

The online side is not trusted. The M-of-N rule is simulated in software for now. For the steps, see the [refill runbook](runbooks/cold-refill.md); after a stolen hot key, see the [stolen-key runbook](runbooks/stolen-hot-key.md).

## Hot shards are kept level

Sweeps all land on one shard, so the others run low. A rebalance moves coins from the fullest shard to a shard below its target. It needs no approval and can only move coins within the same pool. Bitcoin has one shard per pool, so it has no rebalance.
