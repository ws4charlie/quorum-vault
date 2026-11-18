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
2. Make the configured caps equal in all three, then restart the core, the gateway and the cosigners. (If the caps were changed with signatures, see below: the signed caps replace the configured ones until the core and the zone are on the same change.) A cap that is too low for the largest transaction stops a process at start-up with the numbers and the fix.
3. Retry the withdrawals that failed.

## Raise the caps during a fee spike
When the market rate is above `max_fee_rate`, a stuck send cannot be bumped (see [stuck sends](btc-stuck.md)). The zone's approvers can raise the caps with signatures, with no restart.

**What is fixed.** The zone config of each Bitcoin chain has a `fee_caps_change` section: the ceiling and floor of both caps (`min_fee_rate`, `max_fee_rate`, `min_tx_fee_sats`, `max_tx_fee_sats`), `min_approvers` (default 1) and `max_change_age` (default 10m). No signature can go outside them. The caps of the config stay the caps until the first change. The gateway and each cosigner carry the same section (it is part of the zone config). A chain with no such section accepts no change. The core config has a `fee_caps_change` section too, with the approvers' public keys and identities (the same as the zone's), because the core checks the signatures itself:

```json
"fee_caps_change": {"min_approvers": 2, "approvers": {"alice": {"key": "<ed25519 public key, hex>", "identity": "alice@example.com"}, "bob": {"key": "...", "identity": "bob@example.com"}}}
```

**Steps.**
1. See the current caps and sequence number in every database. All must show the same sequence number:
   ```bash
   qv-fee-caps show -config zone.json -chain btc -guard-dsn gateway=$GW_DSN -guard-dsn cosigner-b=$CB_DSN -core-dsn $CORE_DSN
   ```
2. Each of `min_approvers` approvers signs the same change on their own machine, with the next sequence number, within `max_change_age` of step 3 (no database needed):
   ```bash
   qv-fee-caps sign -actor alice -key alice.key -chain btc -max-tx-fee-sats 90000 -max-fee-rate 200 -seq 4 -out alice.json
   ```
   The values must be the same in every file. Each person's key counts once, however many keys they have.
3. Apply the joined files to the gateway, every cosigner and the core, in one command:
   ```bash
   qv-fee-caps apply -config zone.json -guard-dsn gateway=$GW_DSN -guard-dsn cosigner-b=$CB_DSN -core-dsn $CORE_DSN alice.json bob.json
   ```
   Each database writes an audit event that names the approvers who signed. The command applies to the core first, then the zone databases. Between the writes the core and the zone are on different changes, and sends built in that time wait (below); with the core first, a send that was already queued for signing was built under the old change, and the zone, still on it, signs it, so the fewest sends have to be built again. If one database fails, the command says which; run the same command again to finish: a database that has the change is skipped.
4. The next build or bump uses the new caps. A transaction already signed is not touched. Bump the stuck sends.
5. After the spike, lower the caps the same way, with the next sequence number.

**Refused.** A change is refused if it is unsigned or signed by fewer than `min_approvers` people, signed more than `max_change_age` from now, has a sequence number that is not higher than the current one, is outside the config's ceiling or floor, or breaks the start-up rule (`max_tx_fee_sats` at least `max_fee_rate` times the size of the largest transaction; the message shows the numbers). A row put into a database any other way is ignored (the reader logs one `ALERT ... do not carry valid approver signatures` line when the number of such rows changes).

**Core and zone on different changes.** The core stamps the sequence number it built under into every transaction it sends to be signed. The zone refuses one built under another number, with `core and zone are on different fee-cap changes`, and the gateway and each cosigner log one `ALERT` per refusal. Nothing is signed. A withdrawal does not fail: it keeps its hold and waits, and the core forgets the unsent build and builds it again under its current change every few seconds, with one `ALERT` for the withdrawal, until the zone and the core agree and the zone signs it. A bump is retried. A batch built in the window returns its withdrawals to the queue without counting a refusal against them. Sweeps, cold moves and consolidations built in the window fail before broadcast, with their coins released, and are planned again later. If the wait lasts, run `qv-fee-caps show`, then `apply` again to the database that is behind.

**Metrics.** `qv-fee-caps metrics -config zone.json -chain btc ... -out /var/lib/node_exporter/qv_fee_caps.prom` (run it from a timer) writes `qv_btc_fee_cap_max_tx_fee_sats`, `qv_btc_fee_cap_max_fee_rate_sat_vb`, `qv_btc_fee_caps_seq` and `qv_btc_fee_caps_ignored_rows` per database (`store` label), and `qv_btc_fee_caps_diverged`, which is 1 when the databases are on different sequence numbers.

The cold refill signer (`qv-cold`) has caps of its own that a signed change does not move: a refill pays the lower of the config's caps and the signed ones.

## Batches
A signing zone that signs batches (several withdrawals in one transaction) has its own ceilings, `max_batch_outputs` and `max_batch_value_sats`, in the gateway and cosigner config. Both unset means no batches. The core cannot raise them. When they are set, the fee caps above must also let a batch of that many payments reach `max_fee_rate`: the largest batch needs `max_fee_rate` x its size in `max_tx_fee_sats`. A zone that cannot reach it stops at start-up with the numbers and the fix. With the default `max_inputs` of 20 and 50 payments, raise `max_tx_fee_sats` to at least 355200 (in the core too; the start-up message prints the exact number).

The core checks its own `batching.max_outputs` the same way at start-up, so turning batching on with the default caps and 20 outputs also needs `max_tx_fee_sats` raised (in the core, the gateway and the cosigners). See also the [batch runbook](btc-batch.md).
