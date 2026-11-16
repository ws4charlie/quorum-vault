# Runbook: choosing the signing pair, and taking a party out for maintenance

## What this controls

A 2-of-3 keyset (EVM and Solana hot shards) is signed by two of the three parties. The **preferred pair** is the pair the gateway uses for the next job: `A+B` (the default), `A+C` or `B+C`. It is one setting for the whole signing zone, not one per keyset: taking a party out for maintenance concerns every keyset on it at once.

Only approvers of the zone's own config can change it, with the Ed25519 keys that already sign intents. `mpc_route.min_approvers` (default 1) says how many must sign. A change is written to the gateway's guard database with an `mpc.route.changed` event in the zone's audit chain, in one transaction. The gateway checks the signatures again every time it reads the setting, so a row written by anyone else is ignored and raises `ALERT mpc route: rows of the preferred-pair table do not carry valid approver signatures`.

The setting can only lower availability. Every pair includes B or C, and that party's own cosigner still judges every job; party A never follows in a Sign.

## Health rules (automatic fallback)

The gateway probes every party's `Health` every `probe_interval` (default 5s). Settings are in the gateway's `mpc_route` section:

| Key | Default | Meaning |
|---|---|---|
| `fail_count` (N) and `fail_window` (T) | 3 in 30s | A party, or the link a party reports to its peer, is routed away from after N failed checks inside T |
| `recover_count` (M) | 6 | It is routed back only after M good checks in a row; one failure restarts the count |
| `probe_interval`, `probe_timeout` | 5s, 3s | The gateway refuses to start if N failures cannot fit inside T at this rate |

The effective pair is the preferred pair if both its parties and its link are healthy; otherwise the next healthy pair in the fixed order `A+B`, `A+C`, `B+C` (starting after the preferred one, wrapping). If nothing is healthy the route stays on the preferred pair and jobs wait and retry. One failed signature never changes the route. Inside one job the old rule stays: after an availability failure **before signing started** the gateway tries the next healthy pair for that job only; after a REFUSED, CRYPTOGRAPHIC, FROZEN, LIMIT or INTERNAL failure, or an availability failure after signing started, it does not.

## Metrics and alerts

The gateway opens no port. With `-mpc-metrics-file` (env `QV_MPC_METRICS_FILE`) it rewrites a Prometheus text file at every probe round, for a node-exporter textfile collector:

- `qv_mpc_preferred_pair{pair}`, `qv_mpc_effective_pair{pair}`, `qv_mpc_route_degraded`
- `qv_mpc_party_healthy{party}`, `qv_mpc_link_healthy{from,to}`, `qv_mpc_party_failed_checks{party}`, `qv_mpc_party_good_checks{party}`, `qv_mpc_party_last_ok_timestamp_seconds{party}`
- `qv_mpc_health_threshold{name}`: the configured N, T, M and probe interval, so a dashboard shows the rules next to the state

Alert rules are in `monitoring/mpc-routing.rules.yml`. Log lines: `ALERT mpc route differs from the preferred pair`, `mpc route is back on the preferred pair`, `ALERT mpc health: routed away after repeated failed checks`, `mpc preferred pair changed`.

## Take party X out for maintenance

Take B out as the example (use `A+C`); for A use `B+C`; for C no change is needed unless it is flapping, since `A+B` does not use it.

1. Check the current setting and sequence number:
   ```bash
   qv-route show -config gateway.json -guard-dsn "$QV_GATEWAY_GUARD_DSN"
   ```
2. Each approver signs the change on their own machine (sequence = current + 1), then one operator applies all signature files:
   ```bash
   qv-route sign -actor alice -key alice.key -pair A+C -seq 5 -out alice.json
   qv-route sign -actor bob   -key bob.key   -pair A+C -seq 5 -out bob.json   # skip if min_approvers is 1
   qv-route apply -config gateway.json -guard-dsn "$QV_GATEWAY_GUARD_DSN" alice.json bob.json
   ```
   Signatures are valid for `max_change_age` (default 10 minutes) around the signing time; sign again if late.
3. Confirm: the gateway log shows `mpc preferred pair changed`, the metrics show `qv_mpc_preferred_pair{pair="A+C"} 1` and `qv_mpc_effective_pair{pair="A+C"} 1`, and the audit chain has the `mpc.route.changed` event (`qv-gateway verify` checks the chain).
4. Wait for jobs already signing on `A+B` to finish (they are never moved). Then stop B, patch it, start it. B must be reconciled with A and C before it is used again (`Health` shows its keysets `resolved`).
5. Wait until `qv_mpc_party_healthy{party="B"}` and the A to B link are 1 again (`recover_count` good checks).
6. Apply the next change back to `A+B` the same way (sequence + 1) and confirm the metrics.

Never take out two parties: two of three must be up for any signature, and `A+B`, `A+C`, `B+C` each need both of their parties.

## When things go wrong

| Symptom | Meaning and action |
|---|---|
| `qv-route apply` says the sequence is not higher | Someone applied a change first, or a row with a higher number exists. Run `show`, sign again with the number it prints |
| `valid signatures ... needed` | Too few distinct, enabled approvers signed, or a signature is for another pair, sequence or time. Sign again together |
| `ALERT mpc route differs from the preferred pair` | Health rules ruled the preferred pair out. Find the unhealthy party in the metrics and fix it; the route returns on its own after `recover_count` good checks |
| Route will not leave a pair although a party is back | The count needs consecutive good checks; a party that still fails now and then keeps resetting it. Look at `qv_mpc_party_good_checks` |
| `party A signed with peer ... although "C" was asked for` | A runs an old version that ignores the wanted peer. Upgrade the parties before moving the gateway to `A+C` |
| `ALERT mpc route: rows ... do not carry valid approver signatures` | Something wrote to the guard database without approver keys, or an approver was removed or disabled. The gateway ignores those rows and keeps the last valid setting; investigate who has write access to the guard database |

Sessions that keep failing with one party although the health checks pass are counted per suspected party and alerted; the steps for that, including when to take a party out with this runbook, are in [mpc-failures.md](mpc-failures.md).

Rolling back is a new signed change to the pair you want; rows are never edited or deleted.
