# Bitcoin

[中文](zh/bitcoin.md)

Bitcoin has no balances, only coins (UTXOs). Paying is like handing over notes and getting change: a transaction names the exact coins it spends. How a send gets confirmed is on [its own page](bitcoin-sending.md).

<p align="center"><img src="images/bitcoin.png" width="60%" alt="Customer addresses come from a public key. Deposits are credited when confirmed. A withdrawal spends chosen coins and returns change to the hot wallet. Many small coins are merged by consolidation."></p>

## Addresses come from a public key
The core holds the account's extended public key and derives each customer's address on its own, without asking the signers. A test proves the address matches the key the parties derive. A deposit is credited only after enough confirmations. If the chain reorganises deeper than that, scanning stops with an alert, credits stay, and an operator decides.

## A withdrawal spends chosen coins
The core picks coins from the hot wallet, pays the customer, and sends change back to the hot wallet. If the coins cannot cover it, the withdrawal waits for change to come back. Each input is signed under its own derived key, and the signing zone rebuilds the digest of every input itself, which closes the attack of collecting signatures under an understated fee.

## Consolidation merges small coins
A wallet fed by many small payments can hold enough value, yet no single transaction can carry it. Consolidation merges the small coins into one before that happens, and withdrawals keep working meanwhile. Each partition has one hot shard, so there is no rebalance.

## Taproot is not supported
The signing library has no key tweak and no derived Schnorr keys, which deposit addresses need. The cold signer has no matching mechanism either. A spike found little to gain for withdrawals.

## The key can be replaced, and old addresses keep working
One account key stands behind the deposit addresses and the hot wallets, so replacing it changes both. A second key is made by the two parties, and operators activate it with signed records. New customers get addresses of the new key; the old key is kept for a stated period, its addresses are still watched, and what lands on them is swept into the new hot wallet. The old hot wallet is emptied into the new one in the same way as a consolidation. The signing zone judges every step from its own records, so a business side that lies cannot move money to a key the operators did not sign. After the period, and once nothing is left on the old addresses, the old key is retired.
