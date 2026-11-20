# Runbook: the attestation release broker (`qv-attest-broker`)

## What it is
Each MPC party runs in a TEE. Its shares are sealed under data keys; the broker holds, in its own HSM token, one non-extractable wrapping key per party and releases a party's data key only to evidence that (1) verifies against the configured trust roots, (2) carries a fresh broker nonce bound to the caller's pinned TLS key, (3) is bound to the exact request (party, keyset, generations, purpose, blobs, caller key), and (4) shows a measurement that the signed allowlist lists for that party now. The key is returned encrypted to the public key inside the evidence. Every attempt is audited. Design: `research/TEE.md`. The party side comes with task T3; until then nothing calls the broker.

Calls (mutual TLS 1.3, pinned keys): `challenge`, `release` (open blobs), `newkey` (the broker makes data keys, returns each wrapped, and sealed to the evidence key). `newkey` exists so a plaintext data key never travels to the broker for wrapping and no operator tool ever sees one.

## Where it runs
Its own trust zone (own host or cluster, own HSM), outside the party hosts. Only party links reach it (inbound mTLS from the party enclaves' proxies). **One replica**: nonces are in memory, so a second replica would refuse the other's challenges. State: the audit log (a volume, append-only) and the HSM token; the allowlist is a mounted file. A restart voids open challenges only.

## Configuration
JSON, flags `serve -config broker.json`; secrets are files (token PIN `pkcs11.pin_file`, mode 0400; TLS key). Fields: see `internal/attest/broker/config.go`. Pins are SHA-256 of the SPKI, as on every link. `health_listen` (e.g. `127.0.0.1:8444`) serves `/healthz` and `/metrics` for pod probes; no data.

The production build refuses to start without trust roots, without a valid signed allowlist, with `allow_debug`, or with a root marked TEST ONLY. The simulation build (`-tags teesim`) is for dev and CI only and prints a warning.

## Change the allowlist (new measurement, overlap, revoke)
Operators are the Ed25519 keys in `operators` of the config; `min_operators` signatures are needed.
1. Draft with a **higher sequence** than the list in force (`qv-attest-broker allowlist show -in current.json -operators broker.json` prints it):
   `qv-attest-broker allowlist new -seq N -out list.json -entry A,<PCR0 hex>,<not_before>,<not_after> -entry ...`
   Upgrade = keep the old entry and add the new one (overlap). Revoke = leave the old one out.
2. Each operator reviews and signs (the tool prints what it signs): `allowlist sign -in list.json -key operator.key -operator NAME`.
3. Check: `allowlist show -in list.json -operators broker.json` must print `valid`.
4. Replace the mounted file. The broker reloads within `reload_interval` (default 10 s) or on `SIGHUP`, no restart. An unsigned, under-signed, malformed or not-newer list is refused and the previous list stays; this is logged and audited (`allowlist_load`, outcome `refused`). Revocation is immediate for new releases; a running party keeps its keys until it restarts.
Key generation for an operator: `allowlist keygen -key operator.key -pub operator.pub`.

## Audit
`audit_log` is JSON lines, one record per release/newkey attempt (time, party, measurement, nonce, keyset, generations, outcome, failed rule) and per allowlist load, fsynced before a key is returned; if the record cannot be written the release is refused. Each line holds the hash of the previous one: `qv-attest-broker audit verify -file audit.log`. The chain detects edits and removals inside the file, not a cut tail: make the file append-only at the filesystem level (`chattr +a`, or a volume only the broker appends to) and ship it off the host. It holds no key, PIN or evidence.
Metrics (`/metrics`): `qv_attest_broker_events_total{event=...}` (`release_ok`, `release_refused`, `rate_limited`, `reload_refused`...). Alert on refusals and on `reload_refused`.

## Rate limit
Per party, challenge and key calls together: `rate_per_minute` (30) and `rate_burst` (10). A party that restarts needs one challenge and one release per keyset.

## Broker outage
Parties **cannot restart** (they cannot unseal) and cannot create new data keys (DKG, refresh) while the broker is down. **Running parties keep signing**: the data keys are released once at start and live in the enclave's memory, so signing does not call the broker (design: "release once, at start, not per signature"; confirm with T3 when the party code lands). Restore the broker first, then restart parties one at a time, keeping any two parties up (a 2-of-3 set must stay signable). A lost HSM token without a backup makes every wrapped data key unrecoverable: back up the token like any HSM.

## Limits
Simulation proves our code handles evidence correctly, not that real hardware measures what the mock measures. Trust roots are config: whoever can edit them and the allowlist alone controls the broker, so both are operator-signed or change-controlled. A data key is in broker memory for a moment between the HSM and the encryption to the enclave.
