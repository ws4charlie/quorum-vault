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
