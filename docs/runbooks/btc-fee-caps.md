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

The shipped examples carry the section: `internal/gateway/config.example.json` (the bounds, `min_approvers` 2) and `internal/custody/config.example.btc.json` (the approvers, the same names, keys and identities as the zone's enabled approvers, and the same `min_approvers`). A test keeps them in step. Replace the placeholder keys.

**Who runs the commands.** An operator with a database role that may write the fee-cap table and the audit log: the guard databases of the gateway and every cosigner (signing zone) and the core's database (business zone). The service roles cannot: `qv_core` and `qv_worker` only read the core's table, the gateway and cosigner roles read the guard table. On Kubernetes this is a Job or an `exec` in a pod of the signing zone that holds the admin connection strings for both databases; the connection goes outward from the signing zone to the business database, never the other way. The approvers sign on their own machines and send the files.

**Steps.**
1. See the current caps and sequence number in every database. All must show the same sequence number:
   ```bash
   qv-fee-caps show -config zone.json -chain btc -guard-dsn gateway=$GW_DSN -guard-dsn cosigner-b=$CB_DSN -core-dsn $CORE_DSN
   ```
2. The approvers sign **one change**, each on their own machine (no database needed), in turn. The first states it:
   ```bash
   qv-fee-caps sign -actor alice -key alice.key -chain btc -max-tx-fee-sats 90000 -max-fee-rate 200 -seq 4 -out alice.json
   ```
   Alice sends `alice.json` to the next approver. The signing time is part of what is signed, and two people never sign in the same second, so every later approver signs **the same change** with `-like`: the chain, both caps, the sequence number and the signing time come from alice's file, and nothing is typed again:
   ```bash
   qv-fee-caps sign -actor bob -key bob.key -like alice.json -out bob.json
   ```
   Before it signs, the tool prints in plain words what it signs (chain, both caps, sequence, signing time and how long ago that was). Read it and compare it with what you agreed; do not sign if it differs. A flag that disagrees with the file (`-max-fee-rate 300` next to a file with 200) stops the tool with nothing signed; the same approver cannot sign the same file twice. `-signed-at UNIX` is the other way: the first approver passes the time to the others, who type all values again with the same `-signed-at`. The tool checks the shape of alice's file but cannot check her signature (it has no approver keys): `apply` checks every signature, and a file changed after she signed it fails there with `valid signatures ... needed`.

   **Time.** The change must be applied within `max_change_age` (default 10 minutes) of the signing time, which is the time of the *first* signature; the clock does not restart for later approvers. Agree the numbers first, then start the round. If the time runs out, the first approver signs again with the same values and a new time (or a new `-signed-at`) and the others follow with `-like` the new file. Each person's key counts once, however many keys they have.
3. Apply the joined files to the gateway, every cosigner and the core, in one command:
   ```bash
   qv-fee-caps apply -config zone.json -guard-dsn gateway=$GW_DSN -guard-dsn cosigner-b=$CB_DSN -core-dsn $CORE_DSN alice.json bob.json
   ```
   Each database writes an audit event that names the approvers who signed. The command applies to the core first, then the zone databases. Between the writes the core and the zone are on different changes, and sends built in that time wait (below); with the core first, a send that was already queued for signing was built under the old change, and the zone, still on it, signs it, so the fewest sends have to be built again. If one database fails, the command says which; run the same command again to finish: a database that has the change is skipped.
4. The next build or bump uses the new caps. A transaction already signed is not touched. Bump the stuck sends.
5. After the spike, lower the caps the same way, with the next sequence number.

**What an operator sees while the two sides differ** (run in the e2e tests `TestFeeCapsApplyWindow...`): after `apply` to the zone only, `show` prints the zone databases at the new sequence number and the core at the old one, then `WARNING: the databases are on different sequence numbers`; `metrics` has `qv_btc_fee_caps_diverged 1`; the gateway logs `ALERT: the zone refused a transaction built under other fee caps than its own` per refusal, and the worker logs `ALERT: the zone refused a withdrawal built under other fee caps than its own` once per waiting withdrawal. The withdrawal stays in its hold and goes out a few seconds after the last database has the change. The order does not matter for the outcome: zone first and core first were both run. Nothing is restarted.

**Refused.** A change is refused if it is unsigned or signed by fewer than `min_approvers` people, signed more than `max_change_age` from now, has a sequence number that is not higher than the current one, is outside the config's ceiling or floor, or breaks the start-up rule (`max_tx_fee_sats` at least `max_fee_rate` times the size of the largest transaction; the message shows the numbers). A row put into a database any other way is ignored (the reader logs one `ALERT ... do not carry valid approver signatures` line when the number of such rows changes).

**Approvers revoked in the zone.** When the zone uses the signed approver registry (`qv-approvers`, [approvers](approvers.md)), the zone counts only the effective approvers; the core checks changes against the list in its own config. What follows (run in `TestFeeCapsRevokedApprover...`):
- `qv-fee-caps apply` to every database checks each zone database with its own effective set first: a change signed by a revoked approver is refused with `change refused by gateway, nothing was applied`, and nothing is written, the core included.
- Written to the core alone (`-core-dsn` only, or by hand), the core accepts it, because it knows only its configured list. The zone does not have it, so the core and the zone differ and sends wait, as in the window above. This stalls sends but cannot raise what the zone signs: the zone's caps are its own.
- Revoking an approver also changes what the zone sees of earlier changes: a change that now has fewer than `min_approvers` valid signatures is ignored (`show` warns, `qv_btc_fee_caps_ignored_rows` is above 0) and the zone falls back to the previous valid change, or the configured caps. The core still has it. Sends wait until it is fixed. **After revoking an approver, apply a new fee-cap change, with the next sequence number, signed by the approvers who are left, to every database.** Then both sides agree again and the waiting sends go out.
- Making the core follow the registry is a follow-up: the registry is in the signing zone's guard database and the core cannot read it. The apply-time check above closes the way in through the tool.

**Core and zone on different changes.** The core stamps the sequence number it built under into every transaction it sends to be signed. The zone refuses one built under another number, with `core and zone are on different fee-cap changes`, and the gateway and each cosigner log one `ALERT` per refusal. Nothing is signed. A withdrawal does not fail: it keeps its hold and waits, and the core forgets the unsent build and builds it again under its current change every few seconds, with one `ALERT` for the withdrawal, until the zone and the core agree and the zone signs it. A bump is retried. A batch built in the window returns its withdrawals to the queue without counting a refusal against them. Sweeps, cold moves and consolidations built in the window fail before broadcast, with their coins released, and are planned again later. If the wait lasts, run `qv-fee-caps show`, then `apply` again to the database that is behind.

**Metrics.** `qv-fee-caps metrics -config zone.json -chain btc ... -out /var/lib/node_exporter/qv_fee_caps.prom` (run it from a timer) writes `qv_btc_fee_cap_max_tx_fee_sats`, `qv_btc_fee_cap_max_fee_rate_sat_vb`, `qv_btc_fee_caps_seq` and `qv_btc_fee_caps_ignored_rows` per database (`store` label), and `qv_btc_fee_caps_diverged`, which is 1 when the databases are on different sequence numbers.

The cold refill signer (`qv-cold`) has caps of its own that a signed change does not move: a refill pays the lower of the config's caps and the signed ones.

## Batches
A signing zone that signs batches (several withdrawals in one transaction) has its own ceilings, `max_batch_outputs` and `max_batch_value_sats`, in the gateway and cosigner config. Both unset means no batches. The core cannot raise them. When they are set, the fee caps above must also let a batch of that many payments reach `max_fee_rate`: the largest batch needs `max_fee_rate` x its size in `max_tx_fee_sats`. A zone that cannot reach it stops at start-up with the numbers and the fix. With the default `max_inputs` of 20 and 50 payments, raise `max_tx_fee_sats` to at least 355200 (in the core too; the start-up message prints the exact number).

The core checks its own `batching.max_outputs` the same way at start-up, so turning batching on with the default caps and 20 outputs also needs `max_tx_fee_sats` raised (in the core, the gateway and the cosigners). See also the [batch runbook](btc-batch.md).
