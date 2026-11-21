# Runbook: sessions keep failing with one MPC party

## What is counted and what it means

Every party counts each failed peer session once, in `qv_mpc_party_session_failures_total` (served on its `metrics_listen` port), and the gateway counts each failed sign call in `qv_mpc_gateway_sign_failures_total` (its metrics file, next to the routing metrics). Counters only grow; Prometheus reads them with `increase()`. A restart resets them, which `increase()` handles.

| Label | Values | Meaning |
|---|---|---|
| `party` | A, B, C | The party that counted the failure |
| `side` | `coordinator`, `follower` | The party opened the session, or answered it |
| `op` | `sign`, `dkg`, `refresh`, `reconcile`, `other` | `other` is derive, node export, unfreeze and freeze notices |
| `peer` | A, B, C, `none` | **The suspect**: the party the failed message came in from, or the link that failed. `none`: no single party (a limit or a check before any peer was asked, or a three-party session) |
| `kind` | `TRANSPORT`, `UNAVAILABLE`, `CRYPTOGRAPHIC`, `REFUSED`, `LIMIT`, `INTERNAL`, `FROZEN` | See below |
| gateway `pair` | `A+B`, `A+C`, `B+C` | The pair the failed call went through |

| Kind | What it says |
|---|---|
| `TRANSPORT`, `UNAVAILABLE` | The peer or the link did not answer, a timeout, or the peer's own dependency (its cosigner, its database) is down. Nothing was signed |
| `CRYPTOGRAPHIC` | A check on the peer's data failed (proof, parsing, final signature). The keyset is frozen on every party that holds it |
| `REFUSED` | A cosigner (or the party's own check, or a member's check of an admin file) said no. Policy at work; nothing ran. The message names the party (`party C: admin authorization: …`) and is never a timeout: a key ceremony that times out did not hear a refusal |
| `LIMIT`, `INTERNAL`, `FROZEN` | A limit was hit, a bug or a bad request, or the keyset is already frozen |

**The peer is a suspect, not proof.** cb-mpc aborts without blame: a failed message tells where it came in, not who made it bad. The cause can equally be the reporting party, the link, or the third party. Nothing in the signing zone reads these counters: no freeze, route change or refusal depends on them. Humans act on the alerts.

Reading the numbers: a failed session is counted by both parties that took part (A counts peer B, B counts peer A). The recording rules sum them two ways: per link (`qv_mpc:link_session_failures:increase{5m,1h,24h}` by party, peer, kind) and per suspect (`qv_mpc:peer_session_failures:increase{5m,1h,24h}` by peer, kind). A party that is the common factor of every failed link has the highest per-suspect number; the per-link numbers show which of its links. If only one link fails and the two ends point at each other, the link (or both hosts) is as likely as either party. Failures of a party that is down also pile up on the other parties' reconciliation retries; a party the health checks already rule out is left to `QVMpcPartyUnhealthy`.

## Where it is and how to tune it

- Rules and alerts: `monitoring/mpc-blame.rules.yml`; tests: `monitoring/mpc-blame.rules.test.yml` (`make test-monitoring`).
- Thresholds are the four `vector(...)` numbers at the top of the rules file (series `qv_mpc_blame:threshold{name}`). Change them there; the alerts read them from nowhere else. The `for:` times are in the alerts.

| Alert | Fires when | Default and why |
|---|---|---|
| `QVMpcPeerCryptographicFailures` (page) | 1 or more cryptographic failures with one peer in 1 h | At the first one. It is the one kind that can mean a bad or hostile party, and the keyset is already frozen |
| `QVMpcPeerAvailabilityFailures` (page) | 5 or more TRANSPORT/UNAVAILABLE in 5 min with one peer, for 10 min, and the health checks still pass | A restart or deploy gives a few at once and stays below; a flaky link or host keeps going |
| `QVMpcPeerRefusals` (ticket) | 5 or more refusals in 1 h | Policy refusals happen; a burst means a party or the gateway asks for what the cosigner does not allow |
| `QVMpcPeerOtherFailures` (ticket) | 3 or more LIMIT/INTERNAL/FROZEN in 1 h | Not the network and not a verdict |
| `QVMpcGatewayPairCryptographicFailures`, `...AvailabilityFailures` | The same two rules, per pair, on the gateway's own count | Also covers calls that never reached a party |
| `QVMpcBlameMetricsMissing` (page) | Fewer than three parties are being collected for 5 min | A missing counter raises nothing, so this says so |

A local Prometheus with these rules: `make monitoring-up` (read-only; it scrapes the parties' `metrics_listen` ports and the gateway's metrics file through node-exporter).

## When an alert fires

1. **Read the alert.** Which kind, which peer. Open `qv_mpc:link_session_failures:increase1h` by party and peer to see which links fail, and `qv_mpc_party_healthy`, `qv_mpc_link_healthy` and the party logs (`session` lines with `kind`, `ALERT` lines) around the time.
2. **`CRYPTOGRAPHIC`.** The keyset is frozen; nothing signs on it until a human unfreezes it. Follow [mpc-keyset-freeze.md](mpc-keyset-freeze.md): investigate all three hosts and the links, not only the named peer, then decide between unfreeze, refresh and restore. Until you know, do not unfreeze. If a host looks compromised, take that party out (step 4) and treat it as a stolen share.
3. **`TRANSPORT` / `UNAVAILABLE`.** Check the named peer's host (load, disk, clock, process restarts, the HSM token) and the link between the two parties (network path, certificate expiry, packet loss, mTLS pin changes). `UNAVAILABLE` also means the peer's cosigner or guard database is down: look there. Compare with the third party: if it sees the same peer fail, the peer's host is likely; if only one link fails, the link.
4. **Decide whether to take the party out.** If the failures continue for more than a few minutes and signing is suffering or the party is suspect, move signing to a pair without it with the [signing-pair runbook](mpc-signing-pair.md) (for C: nothing changes while `A+B` signs; for A or B: `B+C` or `A+C`). This works for 2-of-3 keysets (EVM and Solana hot shards). A and B are both needed for 2-party keys (Bitcoin, Solana deposit addresses): those cannot be moved, only fixed. Never take out two parties.
5. **There is no manual freeze.** A keyset freezes itself on a cryptographic failure, nothing else. If you suspect a party but nothing froze, taking it out of the route is the tool; if its share may be exposed, the remedy is the refresh or restore in the freeze runbook.
6. **Bring it back.** After the fix, wait until `qv_mpc_party_healthy` and the link are 1 again (the health rules need consecutive good checks), return the route to the preferred pair the same way, and watch the counters: the 5-minute rate should be flat. Close the alert only then.
7. **`REFUSED` and the others.** Read the cosigner's refusal reasons (`cosigner decision` lines with `allow:false`) and what the gateway sent. A refusal is the check working; a burst means something upstream is wrong, not that the named peer is.

## Limits of these numbers

- A failure is counted when the session ends, so a long stall shows up late.
- A first failure after a party starts is an increase: every series starts at 0.
- The suspect label never grows: no keyset id, job id or any other value is a label.
- The metrics port is plain HTTP and read-only (`GET /metrics`, no other path or method), reveals no secret, and cannot change anything. Bind it to an address only the monitoring host reaches.
