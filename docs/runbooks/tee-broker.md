# Runbook: the attestation release broker (`qv-attest-broker`)

## What it is
Each MPC party runs in a TEE. Its shares are sealed under data keys; the broker holds, in its own HSM token, one non-extractable wrapping key per party and releases a party's data key only to evidence that (1) verifies against the configured trust roots, (2) carries a fresh broker nonce bound to the caller's pinned TLS key, (3) is bound to the exact request (party, keyset, generations, purpose, blobs, caller key), and (4) shows a measurement that the signed allowlist lists for that party now. The key is returned encrypted to the public key inside the evidence. Every attempt is audited. Design: `research/TEE.md`. The party side is the attested sealer (`sealer.type: attested`, below).

Calls (mutual TLS 1.3, pinned keys): `challenge`, `release` (open blobs), `newkey` (the broker makes data keys, returns each wrapped, and sealed to the evidence key). `newkey` exists so a plaintext data key never travels to the broker for wrapping and no operator tool ever sees one.

## Where it runs
Its own trust zone (own host or cluster, own HSM), outside the party hosts. Only party links reach it (inbound mTLS from the party enclaves' proxies). **One replica**: nonces are in memory, so a second replica would refuse the other's challenges. State: the audit log (a volume, append-only) and the HSM token; the allowlist is a mounted file. A restart voids open challenges only.

## Configuration
JSON, flags `serve -config broker.json`; secrets are files (token PIN `pkcs11.pin_file`, mode 0400; TLS key). Fields: see `internal/attest/broker/config.go`. Pins are SHA-256 of the SPKI, as on every link. `health_listen` (e.g. `127.0.0.1:8444`) serves `/healthz` and `/metrics` for pod probes; no data.

The production build refuses to start without trust roots, without a valid signed allowlist, with `allow_debug`, or with a root marked TEST ONLY. The broker also refuses a SoftHSM module unless `QV_ENV` is `dev` or `test` (unset or any other value is production; the module is recognised from what it reports, not its file name), as the gateway and the party do: SoftHSM keeps the wrapping keys in files beside the broker. The simulation build (`-tags teesim`) is for dev and CI only and prints a warning.

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
Parties **cannot restart** (they cannot unseal) and cannot create new data keys (DKG, refresh) while the broker is down. **Running parties keep signing**: the data keys are released once at start and live in the enclave's memory, so signing does not call the broker (design: "release once, at start, not per signature"; the party code does exactly that, see "Party side"). Restore the broker first, then restart parties one at a time, keeping any two parties up (a 2-of-3 set must stay signable). A lost HSM token without a backup makes every wrapped data key unrecoverable: back up the token like any HSM.

## Limits
Simulation proves our code handles evidence correctly, not that real hardware measures what the mock measures. Trust roots are config: whoever can edit them and the allowlist alone controls the broker, so both are operator-signed or change-controlled. A data key is in broker memory for a moment between the HSM and the encryption to the enclave.


# Party side: the attested sealer (`sealer.type: "attested"`)

The enclave is **still simulated**: the only attester that exists is the mock one (`-tags teesim`). A production build has no attester, so a party with `sealer.type: "attested"` refuses to start in it, with the message "this build contains no attester". It never falls back to the PKCS#11 sealer. The AWS Nitro attester is task T7. `pkcs11` stays the default.

## What it does
At start the party makes an evidence key in memory, asks the broker for a challenge, builds evidence bound to the challenge, the request and the TLS key of its broker link, and asks the broker to release the data key of every generation it holds on disk (one `release` per keyset, plus one for the local key). A fresh data directory gets a local key through `newkey`. A new generation (DKG, refresh candidate) gets its key through `newkey` when its share is first sealed. Keys live in locked memory (`mlock`; the start fails with a message if the memory limit is too small: raise `ulimit -l` or grant `CAP_IPC_LOCK`) and are wiped at shutdown. **Nothing key-like is written to disk or logged**: the disk holds ciphertext and each key's wrapped form (useless without the broker's HSM and an allowlisted measurement).

One data key per (party, keyset, generation). After a refresh commits, the old share file (with its wrapped key) is deleted and the key is wiped; it is not requested again. The broker has no "destroy" call, so a copied old file plus a copied wrapped key can still be released to an allowlisted image: see the rollback section.

## Configure
In the party's config, `sealer`:
```
"sealer": {"type": "attested",
  "broker_url": "https://broker.example:8443", "broker_pins": ["<hex SPKI pin of the broker certificate>"],
  "broker_cert_file": "...", "broker_key_file": "...",          // default: the party's own cert_file and key_file
  "attester": {"type": "mock", "ca_dir": "...", "pcr0": "<96 hex>"}}   // simulation builds only
```
The broker must list the pin of `broker_cert_file` under this party (`parties.<role>.caller_pins`) and an allowlist entry for the party's measurement. `QV_HEALTH_LISTEN` probes: `/readyz` answers 503 until the keys are released. `/metrics`: `qv_mpc_party_sealer_ready` and `qv_mpc_party_attest_exchanges_total{outcome}`.

## What an operator sees when release is refused
The party stays not ready and retries with backoff (0.5 s doubling to 30 s). It does not serve, does not reconcile, and its Health call answers UNAVAILABLE. The log says why:

| Log line | Meaning | Do |
|---|---|---|
| `ALERT attested sealer: the broker refused ... measurement is not allowlisted` (metric outcome `refused:allowlist`) | the image is new, or its entry expired or was revoked | add the measurement to the signed allowlist (overlap); the party starts by itself within the backoff, no restart |
| `the broker refused ...` with `broker_code` `verify:*` | the evidence did not verify (debug mode, wrong chain, stale document) | the image or the attester is broken: not an operator fix |
| `broker_code` `rate_limited` | restarts too fast for `rate_per_minute` | wait; the party retries |
| `the broker is unreachable` | network, the broker is down | restore the broker (see "Broker outage") |

The audit log of the broker has the matching record (rule `allowlist:...`, `verify:...`).

## Migrate a party from the PKCS#11 sealer (offline, one way)
The attested sealer never reads PKCS#11 data and nothing migrates at start; a party with old data refuses to start and names this command.
1. Stop the party. Snapshot its data directory: after the command the PKCS#11 sealer cannot read it.
2. Make a second config with the same party, `data_dir` and certificates and `sealer.type: "attested"` (as above).
3. `mpc-party migrate-seal -from old.json -to new.json` (the broker must be reachable and must allowlist the party's measurement).
4. Start the party with the new config.

The command opens every share with the old sealer, seals it under broker-released keys, builds the whole new set in `<data_dir>/.migrate-v2`, opens each new file and compares it with the old plaintext, writes a `COMMITTED` marker and only then moves the files over the old ones (`local.key.json` last). Before the marker the old files are untouched; run the command again after any failure. After the marker it only finishes the moves; if it stops in the middle, the directory holds both formats and no sealer starts on it until you run the same command again. A party with the PKCS#11 sealer that finds a migrated file refuses to start (it never reads a sealed record as an empty one). Do the parties one at a time.

## What is sealed, and what a rollback can and cannot do
Sealing makes a file unforgeable and unreadable; it does not stop deletion or the return of an older copy. Everything below was checked against the code (`store.go`, `freeze.go`, `peer.go`, `reconcile.go`).

| File | State | Why |
|---|---|---|
| `keysets/<id>/g<N>.json` | sealed, own key per generation | the share |
| `keysets/<id>/state.json` | sealed (local key) | the generation pointers and A's commit decision: a forged pointer could make a party use a stale share |
| `freeze/<id>.json` | sealed (local key) | a record that does not open (forged, moved, damaged) counts as **frozen** |
| `jobs/<hash>.json` | sealed (local key) | a forged record would be returned as the signature of a job |
| `keys/<id>.json` | sealed (local key) | the public key a sign is checked against |
| `local.key.json` | wrapped key only | useless without the broker |
| `backups/<id>.json` | plain, public | a note shown by Health; a forged one misreports, signs nothing |

The host with the data directory **can**: delete files (a party loses state, never gains a key), copy an old directory back, replay an old (valid) sealed file.
- **Old directory back (older generation):** the old share opens (the broker releases its key again), but the two parties no longer agree. Reconciliation (`planReconcile`) sees "party A is on generation 1 but party B is on 2" and refuses; the keyset stays unresolved and nothing signs. Tested (`TestAttestedRollbackOfTheDataDirectory`). This depends on the peer: a rollback of **both** parties to the same generation is not detected by anything in the party (design decision D7 / the broker has no counter); the shares of that generation are then valid again.
- **Between two refreshes (same generation):** an older sealed `state.json` or job record of the same generation is accepted. A job record deleted or rolled back means a repeat of that `job_id` signs again (a fresh signature of the same digest, not a key leak); the gateway's own job table stays the authority.
- **Freeze record deleted:** this party is unfrozen locally. The peer's record still refuses (`FROZEN` from B; tested), so one deleted record does not unfreeze the pair; deleting both does. A forged record stays frozen.
- **A refresh in flight:** the candidate file, the decision and the commit are the existing two-phase commit; each failpoint (`after_selftest`, `b_after_candidate_stored`, `a_after_candidate_stored`, `a_after_decision`, `b_after_commit_received`, `b_after_promote`, `a_after_switched_recv`, `a_after_promote`, `b_after_confirm_recv`, `a_after_delete_old`) is run against real processes with the attested sealer (`e2e` `TestAttestedCrashMatrixRefresh` and `...DKG`): every one converges on one generation that signs. The candidate's key is made when its share is sealed (before B says "prepared"), so a broker outage then fails the DKG or refresh cleanly (the old state is kept; not crash-tested with the broker down).

## Deployment shape
- Trust domain: the party (enclave) reaches the broker's zone outward only; the broker's inbound mTLS is the only new path. No new inbound path into the signing zone.
- State: the data directory (volume) holds only ciphertext and wrapped keys; the data-dir lock (one process per directory) still applies. A rolling update or a second replica cannot corrupt it; a restart asks the broker again (one challenge and one release per keyset, within `rate_per_minute`: many keysets at once can be rate limited and are retried).
- Config: JSON and files only; no secret in config, image or log. The broker link needs a certificate name in the certificate catalog (`internal/pki/catalog.go`; not added here).
- Test and production differ only by the build tag (`teesim`: mock attester, test root) and the trust roots in the broker's config; the sealer, the verifier and the broker are the same code.
