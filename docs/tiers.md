# Hot and cold

[中文](zh/tiers.md)

A hot wallet signs all day, so it holds only what the day needs. The rest sits in cold storage, whose key lives offline. Think of a shop's till and its safe.

<p align="center"><img src="images/tiers.png" width="60%" alt="Above its upper limit a hot wallet moves the excess to cold automatically. Below its lower limit it asks for a refill, which people carry across an air gap."></p>

## Bands decide when to move
Each hot wallet has a lower limit, an upper limit and a target.

| Hot balance | What the system does |
|---|---|
| Above the upper limit | Moves the excess down to the target, into cold |
| Between the limits | Nothing |
| Below the lower limit | Raises one alert and opens a refill request |

## Hot to cold needs no approval
The cold address is written into the signing zone's own config, which the business side cannot change. A move can only send coins somewhere safer, so a hijacked core still cannot send "cold" money elsewhere.

## A hot wallet can change its key
On an EVM chain a hot wallet can get a new key without a new set of books. New payments leave from the new key, the old key moves everything it holds to the new one, and only then is it retired. While both exist, the books add up the balance of both addresses. See the [key replacement runbook](runbooks/key-replacement.md).

## Cold to hot needs people
A refill makes coins more exposed, so it goes through a ceremony.
1. The core opens a refill request. One stays open per cold address; on Solana one per asset.
2. An operator exports it as a file, with the current nonce and fees.
3. The file is carried across an air gap to the offline signer.
4. M of N operators approve, and the HSM signs. The offline config alone decides what may be signed.
5. The signed file comes back, is checked against the request, and is broadcast.

The online side is not trusted. The M-of-N rule is simulated in software. See the [refill runbook](runbooks/cold-refill.md); after a stolen hot key, see [that runbook](runbooks/stolen-hot-key.md).

## Hot shards are kept level
Sweeps land on one shard, so the others run dry. A rebalance moves coins from the fullest shard to one below its target, with no approval, only within the same pool. Bitcoin has one shard per pool, so no rebalance.
