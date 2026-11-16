# Runbook: Bitcoin fee caps differ between the core and the signing zone

**Rule: the core and the signing zone fee caps must be equal** (`max_fee_rate`, `max_tx_fee_sats` and `max_inputs` of the Bitcoin chain, in the core config and in the gateway and cosigner config).

## Why
Each withdrawal or hot-to-cold send keeps enough in change to be raised to the fee cap. The core sizes that reserve with its own caps. The signing zone checks it again with its own caps. If the core's caps are lower, it reserves less than the zone needs, and the zone refuses every first send.

## What you see
- Withdrawals fail with a reason that starts `gateway refused` and says `the zone needs at least N` for the change, ending `core and zone fee caps differ: they must be equal`.
- The gateway and each cosigner log one `ALERT: ... fee caps must be equal` line per refused send.
- Nothing is signed, the hold is released, and the coins are available again.

## Fix
1. Compare the Bitcoin fee settings of the core config with the gateway and cosigner configs.
2. Make them equal in all three, then restart the core, the gateway and the cosigners. A cap that is too low for the largest transaction stops a process at start-up with the numbers and the fix.
3. Retry the withdrawals that failed.

## Batches
A signing zone that signs batches (several withdrawals in one transaction) has its own ceilings, `max_batch_outputs` and `max_batch_value_sats`, in the gateway and cosigner config. Both unset means no batches. The core cannot raise them. When they are set, the fee caps above must also let a batch of that many payments reach `max_fee_rate`: the largest batch needs `max_fee_rate` x its size in `max_tx_fee_sats`. A zone that cannot reach it stops at start-up with the numbers and the fix. With the default `max_inputs` of 20 and 50 payments, raise `max_tx_fee_sats` to at least 355200 (in the core too; the start-up message prints the exact number).
