# Runbook: a Bitcoin batch is stuck, or must be cancelled

A batch is one transaction that pays several withdrawals (see [Bitcoin](../bitcoin.md)). It is bumped by itself, as a whole, up to the fee caps. This page is for when that is not enough.

## See the batch
`GET /v2/batches/{id}` lists its status, transaction, members in payment order and, once it confirmed, each member's fee share. A withdrawal shows its `batch_id`.

| Status | Meaning |
|---|---|
| sealed | Members chosen, no coins taken yet. It waits while the hot wallet cannot fund the first member |
| signing | Coins reserved, the signing zone has not finished |
| broadcast | Sent; waiting for confirmations or a bump |
| confirmed | Every member is booked |
| cancelled | A cancel of the whole batch confirmed; the members are back in the queue |
| discarded | Nothing was signed; coins released, members back in the queue |

## Cancel one withdrawal
`POST /v2/withdrawals/{id}/rejections` while it waits in the queue, or while its batch is not signed. The unsigned batch is discarded and the others go back in the same order. Once the batch is signed the answer is 409: cancel the whole batch.

## Cancel the whole batch
`POST /v2/batches/{id}/cancel`.

- Not signed yet: the batch is discarded at once.
- Signed: a cancel spends the same coins back to the hot wallet, and escalates its fee like any cancel, up to the caps. If the batch confirms first, it is booked as usual and nothing is lost.
- When the cancel confirms, the withdrawals return to the queue at their original place. The next batch must spend the cancel's output (the signing zone refuses it otherwise), so it waits for the cancel to confirm.

## When an alert says it cannot be bumped or built
The batch keeps waiting and nothing is voided. Raise the caps (the same in the core, the gateway and each cosigner, see [fee caps](btc-fee-caps.md)) or cancel the batch.

## When the signing zone refuses a batch
Nothing is signed, the coins are released and the members return to the queue. A refusal that names a withdrawal parks that withdrawal with an alert. A refusal that names none parks a withdrawal after the third batch it was in. Read the reason on the job, fix the cause (usually the zone's limits or destination list), and clear the parked reason to resume.
