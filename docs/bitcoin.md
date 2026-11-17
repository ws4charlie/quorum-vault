# Bitcoin

[中文](zh/bitcoin.md)

Bitcoin has no balances, only coins (UTXOs). Paying is like handing over notes and getting change: a transaction names the exact coins it spends.

<p align="center"><img src="images/bitcoin.png" width="60%" alt="Customer addresses come from a public key. A withdrawal spends chosen coins and returns change to the hot wallet. Many small coins are merged by consolidation."></p>

## Addresses come from a public key
The core holds the account's extended public key and derives each customer's address on its own, without asking the signers. A test proves the address matches the key the parties derive. A deposit is credited only after enough confirmations. If the chain reorganises deeper than that, scanning stops with an alert, credits stay, and an operator decides.

## A withdrawal spends chosen coins
The build reserves coins from the hot wallet, pays the customer, and sends change back to the hot wallet. If the coins cannot cover it, the withdrawal waits for change to come back. Each input is signed under its own derived key, and the signing zone rebuilds the digest of every input itself. This closes the attack where signatures are collected under understated fees.

Each send keeps enough in its change to be raised up to the fee cap, so a stuck withdrawal can always be bumped with its own coins. If the hot wallet cannot cover that on top of the payment, the withdrawal waits, and the alert names the reserve as the reason and says how much would release it. The signing zone checks the same thing with its own limits, so a faulty core cannot send a transaction that could never be raised. The core and the zone fee caps must be equal: a core with lower caps reserves too little, and the zone refuses its sends with an alert that says the caps differ (see the [fee caps runbook](runbooks/btc-fee-caps.md)). Each refuses to start if its limits could not carry the largest transaction it may build.

## Stuck or failed transactions

| Situation | Result |
|---|---|
| Stuck | Replaced by a transaction that spends the same coins for a higher fee, paid from the change |
| Replacements used up, or the next fee is over the caps, and the transaction still does not confirm (CPFP on) | A child spends its change back to the hot wallet and pays for both |
| No change to pay from (a transaction made before the reserve existed) | An alert; the withdrawal keeps waiting |
| One input refused after another was signed | A cancel spends the same coins back to the hot wallet |
| The coins were spent by something we did not make | The withdrawal is parked with an alert |

A replacement the node refuses for a fee that is too low is followed by one that pays more than the highest fee refused so far, even after a restart. A cancel does the same: if it is refused or stays unmined, the next cancel pays more than every earlier attempt and every refused cancel. Both stop at the fee caps, with one alert, and nothing is voided because of a cap.

## A child can pull a stuck send in
Replacing a transaction needs a new signature for all of it and is limited to a few attempts. A second way out is a child: a new transaction that spends the stuck one's change back to the same hot wallet and pays a fee high enough for the pair to be worth mining. It is off by default and has to be switched on with a waiting time. It starts once the replacements are used up, or the next one would be over the caps, and the transaction has stayed unconfirmed for that time. It works for a single withdrawal and for a whole batch.

It does not go beyond the caps. The pair together may not pay more than one transaction of their combined size may, and the child alone stays under the usual limits. A transaction that already pays the rate ceiling therefore leaves no room for a child: both are held to the same ceiling, and the pair cannot pay a higher rate than its first part. The core says so and does not build one.

The signing zone needs no approval for a child, because it can only keep the money where it is. It signs only a child that has no payment, spends the change of a transaction it signed itself, pays back to that hot wallet, and stays within its own caps for the pair, computed from its own record of the parent. A second child of the same transaction, or a child of a change something else already spent, is refused.

- **One child per transaction.** The child may be replaced by a child that pays more. A child never has a child.
- **The send is not replaced any more** once its child was sent, because that would orphan it. A cancel is still possible: it replaces both, so it must pay more than the two together.
- **Booking.** The child's fee is a cost of the withdrawal or batch it pulled in, booked with it once both confirm. Its output is the hot wallet's coin that takes the place of the change. If a cancel confirms instead, only the cancel's fee is booked.

## Batches pay several withdrawals in one transaction
Batching is off by default. When an operator turns it on for a hot wallet, approved withdrawals wait in a queue, oldest approval first, and one transaction pays many of them. That saves fees, because the inputs and the change are paid for once.

A batch is sealed when the oldest withdrawal in the queue has waited the configured time, or when enough are queued, whichever comes first. It takes the longest run from the front of the queue that the wallet's confirmed coins can fund, with the same fee reserve as a single send. Nobody is skipped: if the first withdrawal cannot be funded, the batch waits. A limit on how many batches of one wallet are in flight keeps each batch on confirmed coins only. A wait of zero means one withdrawal per transaction, as before.

Approval stays per withdrawal. The signing zone signs a batch only if every payment in it is exactly one withdrawal that was approved, in the same order, with at most one change back to the hot wallet, and within the zone's own limits on payments, total value and fee, which the core cannot raise. A withdrawal id the zone has signed is not signed again, except in a replacement of the same batch.

| Situation | Result |
|---|---|
| Cancel one withdrawal in the queue | It leaves the queue; its hold is released |
| Cancel one withdrawal of a batch nobody has signed | The batch is discarded and its coins released; the others return in the same order |
| Cancel one withdrawal of a signed batch | Refused: only the whole batch can be cancelled |
| Cancel the whole batch after it was signed | A cancel spends the same coins back to the hot wallet; the withdrawals return to the queue at their place and are paid again once, by a batch that spends the cancel's output |
| Stuck batch | Replaced as a whole: same coins, same payments, less change, within the fee caps |
| One withdrawal fails the destination check, before sealing or before signing | It is removed from the batch and parked with an alert |

Each withdrawal is booked once, when the transaction confirms, with its own share of the fee. The shares add up to the real fee, and any attempt, not only the last, may be the one that confirms.

A batch shows on the chain that its recipients were paid together, with the same inputs and one change. Turn batching on only if that is acceptable. What to do with a stuck or cancelled batch is in the [batch runbook](runbooks/btc-batch.md).

## Consolidation merges small coins
A wallet fed by many small payments can hold enough value, yet no single transaction can carry it. Consolidation merges the small coins into one before that happens, and a withdrawal keeps working meanwhile. Each partition has one hot shard.
