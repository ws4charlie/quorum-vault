# Runbook: the attestation release broker (`qv-attest-broker`)

## What it is
Each MPC party runs in a TEE. Its shares are sealed under data keys; the broker holds, in its own HSM token, one non-extractable wrapping key per party and releases a party's data key only to evidence that (1) verifies against the configured trust roots, (2) carries a fresh broker nonce bound to the caller's pinned TLS key, (3) is bound to the exact request (party, keyset, generations, purpose, blobs, caller key), and (4) shows a measurement that the signed allowlist lists for that party now. The key is returned encrypted to the public key inside the evidence. Every attempt is audited. Design: `research/TEE.md`. The party side is the attested sealer (`sealer.type: attested`, below).

Calls (mutual TLS 1.3, pinned keys): `challenge`, `release` (open blobs), `newkey` (the broker makes data keys, returns each wrapped, and sealed to the evidence key). `newkey` exists so a plaintext data key never travels to the broker for wrapping and no operator tool ever sees one.

## Where it runs
Its own trust zone (own host or cluster, own HSM), outside the party hosts. Only party links reach it (inbound mTLS from the party enclaves' proxies). **One replica**: nonces are in memory, so a second replica would refuse the other's challenges. State: the audit log (a volume, append-only) and the HSM token; the allowlist is a mounted file. A restart voids open challenges only.

## Configuration
JSON, flags `serve -config broker.json`; secrets are files (token PIN `pkcs11.pin_file`, mode 0400, or 0440 as a Secret volume under `fsGroup` shows it; TLS key). Fields: see `internal/attest/broker/config.go`. Pins are SHA-256 of the SPKI, as on every link. `health_listen` (e.g. `127.0.0.1:8444`) serves `/healthz` and `/metrics` for pod probes; no data.

The production build refuses to start without trust roots, without a valid signed allowlist, with `allow_debug`, or with a root marked TEST ONLY. The broker also refuses a SoftHSM module unless `QV_ENV` is `dev` or `test` (unset or any other value is production; the module is recognised from what it reports, not its file name), as the gateway and the party do: SoftHSM keeps the wrapping keys in files beside the broker. The simulation build (`-tags teesim`) is for dev and CI only and prints a warning.

## The allowlist (which builds may get the keys)
Everything in this section runs in the **simulated** enclave today (`teesim`): a release's measurement is a hash the simulation computes, not a number from Nitro hardware. The signed-list rules, the tool and the procedures are the production ones; what changes with real Nitro (task T7) is how the measurement is computed and checked (see "What simulation cannot prove" at the end).

### The file
A signed JSON list. Entry: `party`, `measurement` (PCR0, hex), `version` (the release, e.g. `v1.4.0`), `not_before`, optional `not_after` (valid-until; none = no end) and `status` (`active`, or `revoked`). The list has a `seq` that must rise with every list. The operators sign `qv-attest-allowlist-v2` + seq, signed-at and every entry field with Ed25519: the same pattern as the approver registry (`internal/gateway/approvers.go`: named operator keys, `min_operators` distinct valid signatures, a domain-tagged message). Changing any field after signing, the version and the status included, breaks every signature.

The broker, for the list in `allowlist_file`:
- **Refuses** an unsigned, under-signed, malformed list, and a list whose `seq` is not higher than the one in force. It keeps serving the last good list, counts `reload_refused`, and audits `allowlist_load` / `refused` with the reason.
- **Refuses an old list at a restart too.** The floor is the highest `seq` the audit log records as loaded. A host that puts an older (once valid) list back while the broker is down gets "refusing to start: allowlist sequence N is older than M". Limit: the floor lives in the audit log; a log that is cut or replaced loses it, so keep the log append-only and shipped off the host (see "Audit").
- **Exposes the version in force:** metric `qv_attest_broker_allowlist_sequence`, and `GET /status` on `health_listen` (JSON: sequence, signed-at, loaded-at, counts, every entry with its release version and state, refusals by rule). No key or evidence in either.

Entry states in `/status`: `allowing`, `not_yet_valid`, `expired`, `revoked`. A **revoked** entry refuses its (party, measurement) whatever any other entry says; revocation wins over an overlap, and it is permanent for that measurement (a fixed build has a new measurement; to undo a mistaken revocation, sign a new list that leaves the revoked entry out).

### The tool (`qv-attest-broker allowlist ...`)
| Command | Does |
|---|---|
| `show -in list.json -operators broker.json [-against current.json]` | prints entries, how many allow now, whether the signatures are enough (`valid` / `NOT VALID`), and the difference to the list in force |
| `add -in current.json -out next.json -party P -measurement HEX -version V [-not-before T] [-not-after T]` | copy with the new entry, `seq` + 1, **no signatures** |
| `expire -in ... -out ... -party P -measurement HEX -not-after T` | set (or move) valid-until of that measurement |
| `revoke -in ... -out ... -party P -measurement HEX` | add a revocation (the entry it revokes stays as the record) |
| `sign -in next.json -key operator.key -operator NAME [-against current.json]` | **prints what it signs** (and the difference to the list in force), then adds this operator's signature; run it by each operator in turn: the co-signature |
| `new -seq N -out list.json -entry P,PCR0,NOT_BEFORE,NOT_AFTER[,VERSION[,STATUS]]` | a list from scratch (first list, break-glass) |
| `touch -in ... -out ...` | the same entries, `seq` + 1 (keeps several brokers' lists in step) |
| `keygen -key operator.key -pub operator.pub` | a new operator key (never overwrites) |

Each operator reviews the printed difference, not the file: `sign ... -against current.json` prints `+` for an added entry, `~` for a changed window, `-` for an entry left out, and warns when `seq` is not higher. Key files must be mode 0600. A file with a field the tool does not know (a misspelled `not_after` or `status`) is refused by every command, by the broker too: nothing is read as a default.

### From a release to an entry
1. The release (`release.md`) has a signed manifest. Check it first (`deploy/images/verify-release.sh`): the next step reads the digest from it.
2. Compute the measurement from **the build that actually runs** and **the party's measured configuration** (peer pins, caller pins, admin keys: different for every deployment and every party). There are two builds, with different bytes and so different measurements; never mix them:
   - **Simulated enclave (the only one that runs today):** the party built with `-tags teesim`. It is never published: the release rules refuse a tee-sim image. Build it from the release commit and measure it:
     `docker buildx build -f deploy/images/Dockerfile --target bins --output type=local,dest=bins .`
     `deploy/images/measure-release.py binary --binary bins/mpc-party-teesim --config party-A.json`
     It prints SHA-384 over the binary and the config, each preceded by its 8-byte length: the formula the simulated party computes at start and `qv-attest-ca measure -binary mpc-party -config party-A.json` prints (a test pins one vector in the script and in Go; the tee-sim e2e checks the script against the running party). Anyone can do it, with docker and python.
   - **Production release (`mpc-party` of the signed manifest):** `measure-release.py image --manifest release-vX.Y.Z.json --config party-A.json` pulls `mpc-party@sha256:...` by digest and measures `/usr/local/bin/mpc-party`. **Today nothing can use this value**: that binary has no attester and refuses `sealer.type: "attested"`, so no party of this image can ask the broker for a key, and the value is on no allowlist. It shows the shape of what task T7 does with the AWS tooling (PCR0 of the enclave image built from this digest). Do not put it on a simulated allowlist: a party that runs the tee-sim build would not match it, and one that matches runs no enclave.
3. Two independent builders must print the same value: `deploy/images/build.sh repro` builds every binary twice from scratch and fails unless the SHA-256 of each binary **and the simulated measurement (`mpc-party-teesim`) over a fixed configuration** are equal (CI job `repro`, run on every change to the images). A different value means a build input moved: do not release.
4. The manifest names both inputs in `partyMeasurement`: `production` (image digest, binary, status "unusable today") and `simulated` (the tee-sim binary, formula, recipe, status). Their `pcr0` is `null` on purpose (per deployment).

### Upgrade a party release without stopping signing
Rule: **add the new, restart one at a time, then set valid-until on the old.** Tested by `TestTEESimRollingUpgradeKeepsSigning` (the `tee-sim` lane): signing works at every step.
1. Compute the new measurement for A, B and C (above). Draft: `allowlist add -in current.json -out next.json -party A -measurement <new> -version vX.Y.Z` (the list holds every party, add one entry per party; one broker per party lists only its own). Sign with `min_operators` operators (`sign ... -against current.json`), put the file in place. The broker reloads within `reload_interval` (10 s) or on `SIGHUP`; check `/status` shows the new `allowlist_seq` and the entries `allowing`. Both builds are now allowed (overlap).
2. Restart the parties **one at a time**, the one that is not the coordinator first (B, C, then A), and wait until the party is ready (`/readyz`, `qv_mpc_party_sealer_ready 1`) before the next. While one restarts the other two sign (2-of-3); never restart two at once.
3. When all three run the new build and the release is accepted, set valid-until on the old measurement (`expire ... -not-after <time>`, e.g. in 7 days: that is also the rollback window). After that time the old build gets `allowlist:expired`.
Mixed builds: with the three parties on two builds, **every build is allowed and signs**; the broker does not look at what the other parties run.

**Wire compatibility is the operator's check, not a broker rule.** Parties do not negotiate a protocol version; Health shows each party's `Version` and the pinned cb-mpc commit, and nothing compares them. A mixed set signs only if the two builds speak the same MPC messages: same cb-mpc commit and no change of the party-to-party message format. The simulated test builds differ by one byte, so it proves the broker and sealer mechanics and **not** wire compatibility. Rule for a release: its notes say "compatible with vPREV: yes/no". If no, a rolling upgrade is not safe: use the cb-mpc upgrade procedure (a planned stop of the affected keysets), and still add the measurements first.

**Sealed state written by the old build opens under the new one.** The broker's wrapping key is per party in its HSM token; a data key is released for (party, keyset, generation): `wrapAAD(party, keyset, generation)` in `internal/attest/broker/hsm.go` is the only binding, the measurement is only checked against the allowlist and is not part of the key or the blob. So no share is re-sealed on an upgrade (research/TEE.md decision: "the HSM key is not derived from the measurement"). The test shows it: each party restarts on the new build with the same data directory and becomes ready.

### Revoke
`revoke -in current.json -out next.json -party A -measurement <bad>`, sign, put in place. The broker answers the **next request** with `allowlist:revoked` (audit `refused`, metric `qv_attest_broker_refusals_total{rule="allowlist:revoked"}`).
- A **running** party keeps its data keys in memory and keeps signing. **How long: until it restarts, without a bound.** The party attests once at start, there is no lease, no renewal and no periodic re-attestation (`research/TEE.md`: "release once, at start, not per signature"). A revocation that must stop a party now needs the operator to stop it too (stop the process or enclave; on Nitro terminate the instance), then it is refused at its next start.
- **Decision: no lease now.** A bounded lease (the broker returns the key with an expiry, the party asks again before it ends and wipes its keys if refused) is the clean fix, but it changes the party's sealer (`internal/server`, not in this task's files), needs the party to stop serving safely in the middle of a signing round, and a broker outage would then stop signing within one lease. It is listed as backlog: broker `expires_at` in the release response, party renewal loop and wipe, a lease length in the broker config, the failure mode when the broker is down (keep a grace period). Until then the limit is stated here and in `docs/limits.md`.
- What the revoked party's data keeps: nothing is deleted. Its sealed files and wrapped keys stay valid; a later allowed build opens them.

### Rollback (downgrade) and a bad release
- **Downgrade to an older build is allowed while its measurement is allowed** (its entry is `allowing`). Why: a rollout that goes wrong must be reversible without new signatures from every operator; the old entry stays during the valid-until window for exactly that. After valid-until, a downgrade needs a new signed list that moves it (`expire -not-after <later>`): a deliberate, signed, audited step by `min_operators` operators. The old build never gets a key without a list that says so. Tested: after valid-until the old build is refused, after the list moves it the party starts on it with the data written by the new build.
- **A release found bad after rollout:** (1) revoke its measurement for every party, (2) restart each party **on the previous build** (its entry must be `allowing`: `expire` it later if its window ended), one at a time, (3) check `/status`. Sealed state is **not** lost or changed: it opens under the previous build too (same reason as above). If the bad build wrote bad state (a bug, not a key problem), restore that state from backup (`mpc-backup-restore.md`), not by the allowlist. A revoked measurement never comes back; the fixed release is a new build with a new measurement.
- The data-directory rollback (an older copy of the files) is a different thing: see "What is sealed, and what a rollback can and cannot do".

### Break-glass: the list is wrong and no party can start
Examples: the only allowed measurements are wrong, valid-until passed on everything, a list with a too-high `seq`.
1. A list is accepted if `min_operators` of the operators in the broker's config sign it and its `seq` is higher than the one in force. **No one else can write a list**: not the host, not a single operator, not the broker's admin. So the fix is a new list: `allowlist new -seq <higher than everything ever loaded> ...` (or `add`/`expire` on the last list), signed by `min_operators` operators from their own workstations (their keys are offline files; the tool needs no network), placed in the file the broker mounts; `SIGHUP` or wait `reload_interval`. Running parties are not affected; waiting parties start by themselves within their backoff (no restart).
2. A `seq` that was set too high (a typo, 1000000) is not lowered; sign the next one higher.
3. If fewer than `min_operators` keys are available (lost or compromised keys), the operator set must change: that is a **config change** of the broker (`operators` in `broker.json`: new public keys, a new `min_operators`) under change control, then a broker restart. The audit log floor still applies (the new list needs a higher `seq`). Whoever can edit that config file alone controls the broker (see "Limits"): it must be change-controlled and reviewed like a key ceremony. Keep the offline operator keys in at least `min_operators + 1` places.
4. Never delete the audit log to lower the floor: it breaks the chain (`audit verify` fails) and the broker refuses to start on it.

### Metrics, status and alerts
Exported (`/metrics` on `health_listen`): `qv_attest_broker_allowlist_sequence` (the version in force), `qv_attest_broker_allowlist_signed_at_seconds`, `qv_attest_broker_allowlist_loaded_at_seconds`, `qv_attest_broker_allowlist_entries{state}` (allowing, outside_window, revoked), `qv_attest_broker_allowlist_entry{party,version,measurement,state}` (one series per party, version, measurement prefix and state; the value is the number of entries that share them, normally 1), `qv_attest_broker_refusals_total{rule}`, `qv_attest_broker_events_total{event}` (`reload_ok`, `reload_refused`, `release_refused`...). Alert rules are written by the Metrics-B hand; the list handed over is in the TEE-T6 report.

## Kubernetes: how the signed list reaches the pod
The list is a file the broker reads: `allowlist_file` in `broker.json`. In a pod: a **ConfigMap whose name ends with a hash of its content** (`qv-attest-allowlist-<10 hex>`, immutable, as the other signed settings), mounted read-only at a directory (not `subPath`: a `subPath` mount never updates), the config's `allowlist_file` pointing into it. A new list is a new ConfigMap and a Deployment update that points to it. Because the broker is **one replica** with in-memory nonces, a rollout restarts it and parties wait (their backoff) for a moment. The broker also reloads on `SIGHUP` and by polling (`reload_interval`), so a kubelet-updated mount works without a restart, but the hashed immutable name is the audit trail. Mounts the chart must provide: the config (`broker.json`: `operators`, `parties`, `allowlist_file`, `audit_log`, `reload_interval`), the allowlist ConfigMap, the audit volume (writable, append-only; `/var/lib/qv/broker`), the TLS key and PIN file as Secrets. Probes: `health_listen` `/healthz`; `/status` and `/metrics` for the monitoring. The tool runs on the operators' workstations, not in the cluster; the image has the same binary (`qv-attest-broker allowlist ...`) for a one-off check Job: `show -operators`.

## Audit
`audit_log` is JSON lines, one record per release/newkey attempt (time, party, measurement, nonce, keyset, generations, outcome, failed rule) and per allowlist load, fsynced before a key is returned; if the record cannot be written the release is refused. Each line holds the hash of the previous one: `qv-attest-broker audit verify -file audit.log`. The chain detects edits and removals inside the file, not a cut tail: make the file append-only at the filesystem level (`chattr +a`, or a volume only the broker appends to) and ship it off the host. It holds no key, PIN or evidence.
Metrics: see "Metrics, status and alerts" above. Alert on refusals and on `reload_refused`.

## Rate limit
Per party, challenge and key calls together: `rate_per_minute` (600) and `rate_burst` (100). A party that restarts needs one challenge and one release per keyset (2N+2 calls for N keysets); at 200 keysets the limit adds about 34 s to a start (`docs/measurements/tee-sim.md`). A batch release call is a possible later change.

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

# Run mode tee-sim (SIMULATED enclave, end to end)

The whole signing path with every party on the attested sealer, in simulation. **Nothing here proves isolation**: the evidence is a mock Nitro document signed by a test CA. It proves our code binds keys to a measurement, refuses what it must, and keeps working around an enclave. The list of what it cannot prove is the last section.

## Start it
One command runs the stack, the gateway, anvil and the tests of the lane:
```
make test-e2e-tee-sim                     # the lane (also: make test-e2e-all GROUPS=e2e-tee-sim)
QV_CUSTODY_SIGNER=mpc QV_CUSTODY_TEE=sim make test-e2e-evm TEST=TestMPCRefreshDuringLiveWithdrawals   # any mpc test in this mode
```
`QV_CUSTODY_TEE=sim` (with `QV_CUSTODY_SIGNER=mpc`) is the switch. Without it nothing changes: the default stacks and tests are untouched. What `e2e/mpcstack/tee.go` does, in the order an operator would do it:
1. Builds `mpc-party`, `qv-attest-broker` and `qv-attest-ca` with `-tags teesim` into their own directory (the production party binary is a different file and has no mock: tested), and makes a test CA and three operator keys. **All keys, certificates, PIN files and allowlists are made at setup in the test's temporary directory; none is in the repository.**
2. Starts **one broker per party**, each with its own SoftHSM token (A: `qv-party-1`, B: `qv-party-2`, C: `qv-party-3`; the parties do not use their PKCS#11 tokens in this mode) and its own audit log. Each lists only its own party.
3. Writes an allowlist signed by two of the three operators (`qv-attest-broker allowlist new` and `sign`).
4. **Enrols** each party: `mpc-party tls-init -config enroll.json` (see "TLS key").
5. Writes the real configs, **measures** them and replaces the allowlist by one that holds only these measurements (the enrolment entries are revoked).
6. Starts the three parties and the cosigners. Every start asks the party's own broker for its keys.

## Measurement: what runs
In simulation the measurement (PCR0) is the SHA-384 of the **party binary file and the config file the party was started with**, each preceded by its length (`attest.MeasureImage`). The party computes it itself at start from `os.Executable()` and the `-config` path; the operator who signs an allowlist entry computes the same with `qv-attest-ca measure -binary mpc-party -config party-A.json`, as a release build would publish it. One changed byte of either file gives another measurement: the broker refuses (audit rule `allowlist:...`), the party logs the ALERT line, stays not ready, and releases nothing (test `TestTEESimWrongBinaryOrConfigIsRefused`). The config therefore carries everything the design wants measured: peer pins, caller pins, `admin_keys`, peer addresses.

**Open point for T7.** The design also says the config hash goes into the evidence's `user_data`. That changes the broker's protocol (the broker would need the expected hash per party), so it is not done here. In the Nitro image the config is part of the image and so of PCR0, exactly as it is part of this mock PCR0; a separate `user_data` binding is only needed if the config is NOT inside the measured image. `attest.Attester` is unchanged: T7 replaces the mock with the NSM device and its PCRs.

## TLS key
With `"tls_sealed": true` (attested sealer only; `cert_file` and `key_file` must be empty) the party's TLS private key is **made inside the party** and sealed like the shares, under its local data key. The data directory holds `tls-key.sealed.json` (ciphertext) and `tls-cert.pem` (public). The pin (SHA-256 of the public key) is what the other parties, the gateway and the cosigner pin. At start the key is loaded only after the data keys are released; until then every TLS handshake fails.

Enrolment: `mpc-party tls-init -config enroll.json` (role, `data_dir`, `tls_sealed`, `sealer`), once per party, offline. It attests like a start, makes the key, seals it, prints the pin, and run again prints the same pin and changes nothing. The enrolment config is a different file than the running config, so it has its own measurement: the allowlist holds the enrolment measurement while the ceremony runs and not afterwards. Because the pins of the other parties are in the running config and the config is measured, enrolment must come first: that is why it is a separate step.

Not sealed: the key of the link to the broker (`broker_cert_file`, `broker_key_file`). It is needed before any data key exists. It is a different key, it only authenticates the link, and the broker releases nothing without passing evidence. On Nitro this key can be made in the enclave at each start if the broker accepts any pin with valid evidence; that is a broker change (not done).

## What an operator sees (and the tests that show it)
| Case | Party | Broker | Rest of the system |
|---|---|---|---|
| Binary or config changed by one byte | not ready, Health UNAVAILABLE, `ALERT ... not allowlisted` | refused, rule `allowlist:...` | the other two sign 2-of-3 |
| Debug evidence (zero PCRs) | not ready, `broker_code verify:*` | refused, rule `verify:...` | the other two sign |
| Entry revoked while the party runs | **keeps its keys and keeps signing** (they are in its memory; the broker cannot take them back) | allowlist loaded, no record for the party | nothing changes until the party restarts |
| Entry revoked, party restarts | not ready, `ALERT ... not allowlisted`; comes back by itself within the backoff when the entry is back, no restart | refused, rule `allowlist:...` | the other two sign 2-of-3 |
| Data directory rolled back | keyset unresolved, "party A is on generation 1 but ... 2 (a stale restore?)" | released (the old key is still released: the broker has no destroy call) | the other two sign |
| Broker down at start | not ready, `the broker is unreachable`, retries; no fallback to another sealer | - | the other two sign; the party is ready when the broker is back |
| Restart of one healthy party | attests again, keys released again, ready | one `release` per keyset | signing continues |

Revocation therefore takes effect **at the next start of the party**. To take effect at once an operator revokes and then stops the party (or the whole enclave); a party that must lose its keys now has to be stopped, not only revoked.

## Numbers
`docs/measurements/tee-sim.md` (labelled simulated): party RSS, start-up time with 10, 50 and 200 keysets, sign latency against the PKCS#11 sealer, and what the broker's rate limit does to a start with many keysets.

## What simulation cannot prove: the real-hardware checklist for T7
Each line is something only real hardware, the vendor's service or a real network can show. Do them on the Nitro stack before any production key moves.

| # | Not proven here | Check on real hardware |
|---|---|---|
| 1 | Memory isolation and confidentiality: the mock runs as a normal process, so the host can read its memory | An attempt to read the enclave's memory from the parent instance fails; no debug console; the enclave started without debug mode |
| 2 | That the hardware measures what the mock measures | PCR0 of the built EIF equals the published value; two independent builders get the same value; PCR8 (the signing certificate) is the release key's |
| 3 | The vendor chain, revocation and TCB handling | The broker accepts the Nitro root G1 chain only; a document from another AWS account or a test root is refused; behaviour at certificate expiry |
| 4 | **AWS KMS's own condition evaluation** (if KMS replaces the broker) | A KMS key policy with `kms:RecipientAttestation:ImageSha384` refuses a Decrypt from a different image; CloudTrail shows the call |
| 5 | vsock and proxy behaviour and limits | Throughput and latency of the parent proxy; what happens when the proxy dies mid-session; the enclave's behaviour with no network |
| 6 | EPC, memory limits and real overhead | Party RSS and sign latency inside the enclave against the numbers in `docs/measurements/tee-sim.md`; the enclave's memory size for the largest keyset count; `mlock` inside the enclave |
| 7 | Side channels and physical attacks | Out of scope for tests; record the vendor's statement |
| 8 | Rollback with real storage | The blob store the host controls: an older directory back (same results as the table above), and a rollback of both parties to the same generation (nothing detects it today, D7) |
| 9 | The broker's HSM | The broker on a real HSM, not SoftHSM (the broker refuses SoftHSM in production); the wrapping key is not extractable; the audit chain is archived |
| 10 | Clock and time limits | Evidence freshness with the enclave's real clock; the 60 s nonce TTL against real network delay |
| 11 | The rate limit with many keysets | A real start with the production keyset count against the broker's limit (measured in simulation: 200 keysets start in about 98 s with the defaults 600 per minute, burst 100) |
| 12 | Revocation at once | A procedure to stop a revoked enclave (terminate the instance), since revocation alone does not take its keys away |


# On Kubernetes (charts `qv-attest-broker` and `qv-party` attested mode)

Charts: `deploy/helm/qv-attest-broker` (README there) and the attested mode of `deploy/helm/qv-party` (README, "Attested mode"). **The enclave is simulated**: the only attester is the mock, so the party chart refuses attested mode unless `env` is `dev` or `test`, and then runs only the tee-sim image (`mpc-party-teesim`, referenced by tag). Production cannot render an attested party until the Nitro attester exists (T7).

## Where the broker runs, and why
**One broker per party, in a cluster of its own that is neither the party's cluster nor the business cluster.** Reasons:
- The broker decides who gets a party's sealing key. If the party's own operators ran it they could edit its allowlist or trust roots, and the enclave would protect nothing from them. So it sits in a trust domain the party's host administrators do not control.
- One broker for all three parties would let one administrator release every party's key: 2-of-3 would fall. With one broker per party, a broken broker costs one party. The chart therefore lists exactly one party.
- **Who administers it:** a small group apart from the party-host operators and from the business zone. The allowlist is signed by `min_operators` operator keys (public keys in the chart values); the cluster administrator can stop the broker, not forge an entry. A cluster administrator can still restart it with an older signed list (the list has no counter at start-up): the rollback limit below.
- **What it can reach:** DNS and its HSM, nothing else (default-deny; no other egress rule exists). **What can reach it:** this party's pods on the mutual-TLS port, through a private endpoint (`service.type` LoadBalancer with internal annotations and source ranges, or one cluster's pod selector); optionally one named scraper on the health port. The party calls out to the broker; nothing calls into the party for this.
- Cluster policy kind `broker` (`deploy/policy/qv-policy`) applies: immutable hash-named ConfigMaps, no dev switches, no exec for non-break-glass users.
This is the recommendation the chart implements. It needs the human's confirmation: who owns the three broker clusters (each party's organisation, or one security group).

## Key storage and what a lost volume means
The wrapping key of the party is a non-extractable AES-256 key in the broker's PKCS#11 token (a network or cloud HSM in production: the module comes from a volume you name). The volume `data` holds only the audit log (hash-chained; `chattr +a` is not possible through the chart: ship it off the cluster). A lost audit volume breaks the chain from that point; keys are unaffected. **A lost HSM token without a vendor backup makes every wrapped data key of that party unrecoverable**: the party's shares are then recoverable only from the party's backup (`mpc-party backup`, PVE-encrypted). In development SoftHSM keeps the token on the same volume.

## One replica, and the update
The broker is a single writer: nonces in memory, one audit chain. The chart pins `replicas: 1`; the StatefulSet stops the old pod before it starts the new one. A restart voids open challenges only; parties retry. The PodDisruptionBudget has `maxUnavailable: 0`: a node drain waits for you, because the broker's outage blocks every party restart, DKG and refresh. Check that no party is restarting, then delete the pod yourself.

## Bring-up of a party, in order
1. **Certificates** (`qv-certs`, list below) and the Secrets: the broker's HSM PIN, and for the simulation the test CA (`qv-attest-ca -dir DIR`, outside the repository).
2. **Evidence root ConfigMap** (public PEM, immutable, name ends in the 10-hex hash of the file): `trustRoots.configMap`.
3. **Install the broker** with an allowlist that already holds the party's **enrolment** measurement (below). `helm upgrade --install ... --set-file allowlist.file=allowlist.json`.
4. **Enrol** the party: install `qv-party` with `attested.phase=enrol attested.stopPartyAck=true`. Two ConfigMaps matter: the Job's `enroll.json` is a file, and the measurement is of that exact file plus the binary. Compute it with the same bytes the Job sees: `kubectl get cm <release>-enrol-config-<hash> -o go-template='{{index .data "enroll.json"}}' > enroll.json`, then `docker run --rm -v $PWD:/w --entrypoint /usr/local/bin/qv-attest-ca <tee-sim image> measure -binary /usr/local/bin/mpc-party -config /w/enroll.json`. Sign it into the allowlist first, upgrade the broker, then run the Job. A second run prints the same pin and changes nothing. The Job prints the **pin** on stdout: `kubectl logs job/<release>-enrol-<name>`.
5. Do 4 for all three parties; put the three pins into the peers (`peers.*.pins`), the callers (`callerPins`) and the cosigners (`cosigner.partyPins`) values.
6. **Start the party**: `helm upgrade` with `attested.phase=run` (default). The StatefulSet uses the data volume the enrolment made. It is not ready until the allowlist holds the measurement of the **running** config: read `party.json` from its ConfigMap the same way, measure it, sign a new allowlist (revoke the enrolment entry), upgrade the broker. The party starts by itself within the retry back-off, no restart.
The enrol phase is **first install only**: it renders no StatefulSet, so an upgrade into it on a running party would stop it. The chart refuses that when the StatefulSet exists (`lookup`, only at a real install or upgrade, not under `helm template`), and `tls-init` itself never changes an enrolled directory.

## Changing the allowlist
Each new list is a new immutable ConfigMap (`allowlist.file`), so a `helm upgrade` rolls the broker pod (a minute without a broker; running parties keep signing, restarting parties retry). The in-place reload of a mounted file stays in the binary but the chart does not use it. **Rollback limit:** whoever can run `helm upgrade` can install an older, still validly signed list; the signatures stop forgery, not a return to an old list. Signed versioned lists (T6) address this.

## Migration from the PKCS#11 sealer
1. Allowlist the **running** measurement of the party's new (attested) config; install/upgrade the broker.
2. **Stop the party first, as its own step:** `kubectl scale statefulset <release> --replicas=0` and wait until the pod is gone. Then `helm upgrade` with `sealer.type=attested attested.phase=migrate attested.stopPartyAck=true attested.migrate.partyStopped=true attested.tlsSealed=false` and the old `hsm.*` values. The chart refuses the phase without `partyStopped`, and at a real upgrade also while the StatefulSet has replicas or its pod exists (`lookup`). The release then removes the StatefulSet (the data volume is retained) and runs the Job (two pod retries: a pod that loses the data-directory lock changes nothing; `MigrateSeal` takes the lock first and is resumable) `migrate-seal -from party-pkcs11.json -to party.json`. Snapshot the volume first. The Job is re-runnable; read its log; run again under another `attested.migrate.name` after a failure.
3. `helm upgrade` with `attested.phase=run`: the party starts attested. The migration keeps the file TLS certificate (its pin does not change); moving to a sealed TLS key is a later, separate step (new pin everywhere).

## Chart changes needed outside the new charts (for the lead)
- **`qv-certs`** must issue: (a) `qv-attest-broker-<role>-tls`: the broker's server certificate (tls.crt, tls.key; long-lived, key never rotated: parties pin it); (b) `mpc-party-<role>-broker-link-tls`: the party's certificate for the link to the broker (the broker pins its key). Both in the catalog (`catalog.json`, `internal/pki/catalog.go`).
- **PIN file mode:** `ReadPIN` accepts a PIN file that only its owner, or its owner and one group, can read (0400, 0600, 0440, 0640): kubelet adds the group-read bit to every Secret file under `fsGroup`, so a production broker reads the PIN straight from the Secret volume. Others must have no access and the group no write or execute. The development staging copy in the chart (init container `cat`/`chmod 0400`, the `pin-staged` volume and the `pin_file` path under `/run/qv/pin`) is now unneeded; the chart README lists what can go.

## Still simulated or unproven
The kind lane (`teesim` case, `ci/kind/smoke/teesim.sh`) has run, in a real cluster: three brokers, the enrolment Jobs (sealed TLS keys), signed allowlists, the three attested parties starting without an HSM (so `mlock` works under the chart's security context), a DKG through party A, and a party restart that attests again. **Not proven:** a signature (the gateway's config needs the new pins), the migration Job (`phase=migrate`), the `lookup` guards on a real upgrade from a running party, a private LoadBalancer between clusters, the production PIN-file path (needs the broker change above), real hardware.
