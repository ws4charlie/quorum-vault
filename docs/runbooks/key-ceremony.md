# Runbook: a key ceremony with `qv-party-admin` (DKG, refresh, freeze, unfreeze, the admin set, the wrap key)

The parties' admin calls (`DKG`, `Refresh`, `Unfreeze`) need the signatures of **M of the N admin keys** (`admin_threshold` of `admin_keys`). All signatures cover **one request file** that names everything the call does: the operation, the keyset, for a DKG the scheme and the curve, the deployment (`admin_domain`), the time it was made and expires, and a random nonce. Every party rebuilds what was signed from the call it receives and checks it against its own `admin_keys`, so a changed field, another keyset or another operation fails. Each party accepts a request **once**, also across a restart.

`qv-party-admin` splits the work so that no signing key ever enters a cluster:

| Step | Command | Where | Holds |
|---|---|---|---|
| request | `qv-party-admin request -op dkg\|refresh\|unfreeze -keyset ID [-scheme … -curve …] [-domain NAME] [-valid-for 1h] -out req.json` | any admin's machine | nothing secret |
| sign (M admins, one after the other) | `qv-party-admin sign -key admin.key -in req.json` | each admin's own machine | that admin's signing key |
| check | `qv-party-admin verify -in req.json -config partyA.json -config partyB.json …` (or `-admin-key HEX … -threshold M`) | anyone | nothing |
| send | `qv-party-admin dkg\|refresh\|unfreeze -auth req.json -party A=HOST:PORT@PIN …` | a Job in party A's cluster (chart `operator.job`), or a labelled bastion pod | a caller certificate, the signed file |
| status | `qv-party-admin status -party … [-keyset ID]` | a Job in each party's cluster | a caller certificate |

Two more signed requests change what the parties themselves hold: a change of the **admin set** (below) and a change of the **recovery-key registry** ([mpc-backup-restore.md](mpc-backup-restore.md), "Replacing the recovery key"). Both are sent through party A and verified by every party itself. They use the same request, `sign` and `verify` steps; their `request` and `send` commands are `qv-party-admin admin-set request|send` and `qv-party-admin recovery-key request|send`, and they read the version they extend from the parties (so they need the caller flags `-party … -cert … -key …`).

There is **no admin call that freezes**. A party freezes a keyset itself after a cryptographic failure ([mpc-keyset-freeze.md](mpc-keyset-freeze.md)). Freezing on purpose means stopping the keyset's signing path (the gateway route) and, if a host is lost, taking that party out.

## Who signs, and how the file travels

- **Signers:** M different admins, each with their own key, each on their own machine. The same key twice counts once; the order does not matter; a key that is not in the parties' `admin_keys` makes the whole file refused. Nobody holds two admin keys.
- **The file holds no secret.** It carries public keys, signatures and the request. It travels as an attachment on the change ticket, by chat or by e-mail: admin 1 makes it and signs, passes it to admin 2, who signs and passes it on (`sign` rewrites the file in place and changes nothing else in it). Signing in parallel on copies does not work: pass one file down the line.
- **What a signer checks before signing.** `sign` prints what the signature covers: the operation, the keyset, the domain, the time and the request body (for a DKG the scheme and curve). Compare each with the change ticket. Sign only what matches. `verify` prints the same plus who has signed.
- **Before sending**, anyone can run `verify` against the parties' configuration. `send` runs the same check first and **refuses before it contacts a party** a file with too few signatures, an unknown key, another domain or an expired one.

## How long a file is good for

A request is valid until the expiry set when it was made (`-valid-for`, default **1 hour**). A party refuses a file valid for longer than its `admin_max_validity_seconds` (default 3600) and one issued more than `admin_max_age_seconds` (300 s) ahead of its clock.

- Make the request when the admins are ready to sign it, not days before. A stolen or forgotten file stops working at its expiry.
- A party that **restarts** refuses every file issued before the restart. After a restart (or a rolling change of a party's settings), make a new request.
- A used or failed call may have consumed the file. After any failure, check `status`, then make a **new request**. Never reuse one.
- DKG and refresh themselves can take a minute or more; the validity applies to the **start** of the call only.

## Who is in the room

At least **M admins** (each signs on their own machine) and a **cluster operator** of party A (creates the ConfigMap and the Job; has no signing key). A person from the cluster of party B or C runs the `status` Job in their cluster before and after, so each party's own view is checked by someone who does not control party A. No one has admin on two party clusters ([qv-party chart README](../../deploy/helm/qv-party/README.md), "Operators").

## Before (every ceremony)

1. All parties up: run `status` as a Job in each party's cluster (`operator.job.command=status`). Every party shows its links reachable, the same generation and frozen flag for the keyset, and the same public key for a 2-of-3 keyset. The tool exits non-zero and prints `THE PARTIES DISAGREE` when they do not: stop and find out why.
2. Every signer's public key is in every party's `adminKeys`, and `adminThreshold` is what you expect. Check against the list the parties were configured with (the ConfigMap), not against the file.
3. A caller certificate for the Job: made for this ceremony, pinned in every party's `callerPins` it will talk to, deleted afterwards. Its Secret has `tls.crt` and `tls.key`.
4. `partyPin`: the pin of **party A's** certificate (SHA-256 of its public key), from the certificate catalogue, not from the party. The Job refuses any other server.
5. Backups: a refresh and a DKG change what a backup must hold ([mpc-backup-restore.md](mpc-backup-restore.md)). Know who exports the new generation afterwards.

## DKG (a new keyset)

1. Choose the keyset ID (letters, digits, `.`, `_`, `-`; up to 64) and the scheme: `ecdsa-2of3` (EVM), `ed25519-2of3` (Solana) or `hd` with `-curve` (two-party HD, Bitcoin). All three parties must be online for 2-of-3.
2. Admin 1: `qv-party-admin request -op dkg -keyset hot-7 -scheme ecdsa-2of3 -domain prod -out req.json`, then `qv-party-admin sign -key admin1.key -in req.json`. Pass `req.json` to admin 2: `qv-party-admin sign -key admin2.key -in req.json` (and on, up to M).
3. Anyone: `qv-party-admin verify -in req.json -config partyA.json -config partyB.json -config partyC.json`. It must say `OK`.
4. In party A's cluster: `kubectl -n qv create configmap dkg-auth --from-file=auth.json=req.json`, then install the Job: `helm upgrade --install … --set operator.job.enabled=true --set operator.job.command=dkg --set operator.job.keysetId=hot-7 --set operator.job.scheme=ecdsa-2of3 --set operator.job.authConfigMap=dkg-auth --set operator.job.callerCertSecret=… --set operator.job.partyPin=… --set operator.job.name=dkg-hot-7`. The chart passes the parties' `adminKeys`, `adminThreshold`, `adminDomain` and validity to the tool, which checks the file first. Read `kubectl logs job/…`. The scheme and curve in the Job values must equal the request's; the file decides, and a mismatch is refused.
5. Output: `OK dkg: keyset ID generation 1` and `root_public_key`, preceded by the status of party A. It refuses if the keyset already exists.
6. **After:** the `status` Jobs of B and C show the keyset, generation 1, not frozen, the same public key as the output. Write the public key into the change record. Then follow the caller's runbook (for a hot-key replacement: [key-replacement.md](key-replacement.md), step 2).

`qv-rekey dkg -admin-auth req.json` takes the same file (a request for `dkg` of the keyset it prints, with the scheme and curve it will use; it refuses a file for another scheme).

## Refresh

Same steps with `-op refresh`; the keyset must exist, be unfrozen and be at the same generation on every party. All parties must be online. The result is `OK refresh: keyset ID generation N+1`; the public key must be unchanged. The parties run their own self-test and keep the old shares unless it passed. After: every party shows generation N+1; export the new generation's backup.

## Freeze, and unfreeze

A frozen keyset refuses signing and refresh. **Do not unfreeze until [mpc-keyset-freeze.md](mpc-keyset-freeze.md) says the cause is understood**; unfreezing a compromised party's keyset gives it more tries. To unfreeze: `-op unfreeze`, same steps, M admins. Every member must be reachable; the tool refuses a keyset that is not frozen. After: `OK unfreeze … not frozen on any of the N parties`, and the `status` Jobs of the other parties agree. Jobs the gateway parked stay parked until an operator clears them.

## When it fails

| Output | Meaning | Do |
|---|---|---|
| `1 signature(s), 2 needed` | too few signers (local check, nothing was sent; also the party's reply) | pass the file to the next admin |
| `expired at …` | the file is past its expiry (local check or the party's) | make a new request |
| `valid for …, the parties accept at most …` | the request was made with a `-valid-for` above `admin_max_validity_seconds` | make a new one with a shorter validity |
| `not a configured admin key` | a signer's key is not in that party's `adminKeys` | fix the party's config through its change process; do not widen anything on the spot; the file needs a new signer |
| `the same admin key signed twice` | one admin signed two times | another admin must sign |
| `does not verify for (…)` | the request, keyset, domain or time the party sees differs from what was signed: a changed file, a call with other flags, or a party with another `admin_domain` | check the file with `verify`; make a new request |
| `domain "…": the parties are configured for "…"` | `-domain` of the request is not the parties' `admin_domain` | make a new request with the right domain |
| `this authorization was already used` | the party accepted this file before | check `status`; make a new request only if the operation did not happen |
| `before this party's start` | the party restarted after the file was made | make a new request |
| `party B: …` or `party C: …` in front of a refusal | that member refused the file; party A passes the member's own answer on, with its name, within a second or two (it used to show as a 10 s timeout when C refused) | read the reason after the name and fix that party, not the link; a refusal is never "try again": make a new request |
| `no longer accepts the v1 authorization format` | an old v1 file reached a party with `admin_threshold` set | use `request` and `sign -in`; see the roll-over below |
| `THE PARTIES DISAGREE` | generation, frozen flag, public key or presence differs, or a party did not answer | stop; use [mpc-failures.md](mpc-failures.md); a half-done refresh or DKG is reconciled by the parties on restart, then check again |
| `-auth is required` | `send` runs without a file | get the file from the admins; the Job holds no key and cannot make one |
| `signature(s) from the new admin set, … needed` | an `admin-set` request without enough signatures of the **new** set | the new keys must sign too; pass the file to them |
| `apply the changes in between first`, `old (it cannot be replayed)`, `replaces another admin set` | the request does not fit this party's version of the set | `status`; finish the earlier change (`admin-set request -finish`), then make a new request |
| `the durable admin set … cannot be opened` | the party cannot read `admin-set.json` and refuses every admin call rather than fall back to its configuration | restore the file from the volume's backup, or the break-glass above on all three |

## Roll-over from one-signature (v1) to M-of-N (v2)

The old v1 file (one signature over operation, keyset and time) covers no request field and needs no quorum. A party accepts it only while its settings allow: **unset `admin_threshold` keeps v1 working**; once `admin_threshold` is set, v1 is **refused** unless `admin_allow_v1: true` says otherwise. Every v1 acceptance is logged (`AUDIT admin authorization accepted in the v1 format`) and counted (`qv_mpc_party_admin_auth_accepted_total{version="v1"}`). There is no fallback from v2 to v1: a v2 file that fails is refused.

Every party that takes part checks the file, so the strictest party decides, and there is no window in which a single compromised party or a single stolen key starts a ceremony if the other two have the threshold set. Order for parties A, B and C:

1. **Upgrade all three** to the release with v2 (config unchanged). v1 and v2 both work; v2 with one signature works too (threshold of one). Check with a `status` Job that all three run the new version.
2. **Roll the tool** to the operators and the Job image. Make one real ceremony in v2 (a refresh of a test keyset) with a single signature. Watch the v1 counter on all three parties: it must stay where it is.
3. **Distribute the keys.** Each admin makes a key on their own machine (`head -c 32 /dev/urandom | xxd -p -c 64 > admin.key`, mode 0600), prints its public key with `qv-party-admin pubkey -key admin.key` and gives only that to the change process. `adminKeys` lists all N on all three parties.
4. **Set the threshold on C, then B, then A** (`adminThreshold: 2` in the chart values; each is a config change and a restart). From each party's restart v1 is refused there. Between the steps the parties that already have the threshold refuse single-signature files, so a ceremony in that period needs M signatures anyway.
5. **Prove it:** a refresh with two signatures works; a file with one signature is refused by each party (`1 signature(s), 2 needed`); an old v1 file is refused (`no longer accepts the v1 authorization format`).
6. **Clean up:** if any party needed `adminAllowV1: true` during the roll-over, remove it. The v1 counter should have stayed at zero since step 4.

Key file for `sign`: one line of hex, the 32-byte Ed25519 seed (or the 64-byte private key). The key never leaves the admin's machine.

## Changing the admin set (add, remove, change the threshold)

**The list in the parties' configuration (`adminKeys`, `adminThreshold`) is only the bootstrap set.** A party uses it while it has no durable state. A change of the set is an admin request (`admin-set`), applied by each party to its own durable record (`admin-set.json` in the data directory, beside the replay memory and sealed the same way under the attested sealer). From then on the record wins: a different list in the configuration is **ignored**, the party logs `AUDIT admin set: ... the configuration is IGNORED` at start, `status` shows `(durable state, the configuration's list is IGNORED)` and `qv_mpc_party_admin_config_ignored` is 1. Nobody can change who the admins are by editing a configuration file.

**What a valid change looks like.** The request names the new keys and threshold, the **version** it creates (the party's version plus one; the bootstrap set is version 0) and the hash of the set it replaces. It must carry the signatures of **the current set at the current threshold and of the new set at its threshold** (a key that stays counts for both). The second part keeps a typo in the new keys from locking everyone out: the new keys have to prove they can sign. A change that skips a version, replaces another set than the party holds, changes nothing, or reuses an old version is refused; the old single-signature (v1) format is gone for good on a party once it has applied a change. Every party checks all of this against its own state: party A only carries the request.

1. **Look first.** `qv-party-admin status -party A=… -party B=… -party C=… -cert … -key …`. Every party shows the same `admin set: version N, M of K keys, hash …`. If they differ, finish the earlier change first (below).
2. **Request.** `qv-party-admin admin-set request <the same caller flags> -add NEWKEYHEX -remove OLDKEYHEX [-threshold M] -out set.json`. The tool reads the version and hash from the parties and prints the new set. Check it against the change ticket.
3. **Sign**, each admin on their own machine, in turn: `qv-party-admin sign -key admin.key -in set.json`. Enough admins of the **current** set to reach its threshold, and enough of the **new** set to reach the new threshold. `verify -in set.json -admin-key HEX … -threshold M` (the current set) says whether a party would take it.
4. **Send**, from a Job in party A's cluster (`operator.job.command=admin-set`, `authConfigMap` holding `auth.json`) or a labelled bastion pod: `qv-party-admin admin-set send -auth set.json <caller flags>`. A applies it, then offers it to B and C. The output says per party: `applied`, `already had it`, `REFUSED: <why>` or `UNREACHABLE`; then it asks every party again and says `OK admin-set: all 3 parties are on the same state` or lists who is behind.
5. **After.** Set the new list in the chart values (`adminKeys`, `adminThreshold`) at the next release so the configuration matches the state and the warning stops. Until then nothing is wrong. For `dkg`, `refresh` and `unfreeze` Jobs set `operator.job.live=true` (the tool then checks the file against the set each party reports, not against the stale list in the values).

### A party was down during the change

The change stays on the parties that took it; the others keep the old set. `status` ends with `THE PARTIES DISAGREE … party C is at version 0 … finish it with admin-set request -finish`, and `qv_mpc_party_admin_set_version` differs. Until it is finished **no admin call can succeed** (the new set's signatures are refused by the party that is behind, the old set's by the parties that moved): a mixed state never lets someone act with a set only some parties accept. To finish:

1. `qv-party-admin admin-set request -finish <caller flags> -out finish.json`: the same change again, made for the parties that are one version behind (a request names its own version and predecessor, so it fits exactly them). A party that restarted refuses a file issued before its restart, and a file lives an hour at most: this is a **new** request even though the content is the same.
2. Sign it with the set the party that is behind still has, and with the new set; send it. The parties that already have the change answer `already had it` (no signature is looked at, nothing changes); the one behind applies it.
3. A party more than one version behind needs the earlier requests first, in order (each still needs the signatures of the set it replaces: keep every request file on the change ticket).

A change must also fit in one request: it needs the current threshold of signatures from the current set **and** the new threshold from the new set, a key in both counting for both, and one request carries at most 32 signatures. A set with a threshold above 16 can therefore be replaced in one step only by a set that keeps enough of its keys (17 of 17 replaced by 17 other keys needs 34); `admin-set request` and every party refuse a change that cannot fit, and a party whose threshold is above 16 logs a warning at start. Change such a set in two steps, or lower the threshold first.

Only one change is in flight: `admin-set request` refuses while the parties disagree.

### Break-glass: the current admin set has lost its quorum

Fewer than the threshold of the current admin keys can still sign (keys lost, people gone), so no `admin-set` request can be made. The only way back is to take the decision away from the admin keys, which means **every party's platform operators act together**:

1. **Decide and record.** Two people from different teams approve it on the change ticket, as for a cold ceremony. Say which keys are lost and name the new bootstrap set (new keys made on the new admins' own machines, public keys only). This is the one moment where whoever edits the parties' settings decides who the admins are; the record is what makes it accountable.
2. **Stop all three parties.** Signing for every keyset stops (the gateway parks its jobs); a keyset frozen at that moment stays frozen. Plan for the outage.
3. **On each party, in its own cluster, by the operators of that cluster** (nobody has admin on two clusters, so at least three people): delete `admin-set.json` from the data directory and put the **same** new bootstrap list in `adminKeys` and `adminThreshold`. The recovery-key registry (`recovery-key.json`) is **not** touched.
4. **Start them** and run `status`: every party shows `admin set: version 0 … (bootstrap list of the configuration)` with the same hash. Make one real call (a refresh of a test keyset) to prove the new keys work, then, if you want, change the set in the normal way.

What it costs: an outage of all signing for the length of the stop; access to all three data volumes and settings; and the admin set is, for that moment, only as trustworthy as the platform operators of all three clusters. What it does **not** allow: one party's operator acting alone. Every admin call needs every taking-part party to accept the same signatures, so a party that was reset on its own (its file deleted, its settings changed) refuses what the other two accept and the other two refuse what it accepts; the disagreement shows in `status`. A test does exactly this (`TestAdminSetBreakGlassNeedsEveryParty`): one party reset gets nobody anything, three reset under one list work.

**Limit.** Sealing makes `admin-set.json` unforgeable but not undeletable: someone with write access to one party's data directory can delete it or put back an older copy. That puts that party on the bootstrap list or an older set, visibly (version and hash differ), and alone it cannot act, as above.

## The wrap key (the HSM key that seals each party's shares)

Each party's shares sit on its volume sealed under one AES key that never leaves the party's own HSM token (`qv-share-wrap`). An attacker who can **use** that key (the token and its PIN) and who has the volume opens the shares; replacing the key inside the same token does not cure that, because the attacker can use the new key too (that case is a replacement of the keysets, [key-replacement.md](key-replacement.md)). What replacing the key does cure: the key's policy or custody changed (a custodian of the HSM left, the token's backup was handled), or a copy of the *old* key material may exist somewhere (an HSM backup) that the token no longer needs.

**Decision (K7a).** The research (decision D7) said: document first, build only if needed. `mpc-party migrate-seal` moves a directory from the PKCS#11 sealer to the attested one; it cannot move shares between two keys of the same sealer, because an envelope did not say which key sealed it and the sealer had one key label. Making a new key usable took three small things on top of what `migrate-seal` already does (offline run under the data lock, a staging directory, verification, a commit marker, resumable moves): an envelope that names its key (`"k"`, only when it is not the default, so existing files are unchanged), a configurable label (`sealer.wrap_key_label`), and a destroy of the old key that refuses while anything needs it. So it is built: `mpc-party reseal`, for both PKCS#11 profiles (`softhsm`, `cloudhsm`), tested against the fake of each profile and, end to end, against SoftHSM tokens with real party processes (`TestResealWrapKeyOnRealToken`). The CloudHSM profile has not run on a real cluster (limits page).

**Procedure, one party at a time** (a keyset needs two of three, so never take two parties out together):

1. Snapshot the data volume. `mpc-party reseal -config party.json -status` shows which keys the shares are under.
2. **Stop the party.** `mpc-party reseal -config party.json -new-label qv-share-wrap-2` makes the key in the token if it is not there, opens every share with the key its envelope names, seals it under the new one, opens each result again and compares, and only then replaces the files (staging directory `.reseal-wrap`, marker, moves). If it is stopped at any point, run it again: before the marker it starts over, after it only finishes the moves. A directory half-moved opens in full, because every envelope names its key.
3. Set `"wrap_key_label": "qv-share-wrap-2"` in the `sealer` section of the party's configuration (chart: the party's config value for the sealer; **list for the lead**: the chart has no value for it yet) and start the party. Wait until `status` shows every keyset resolved and sign once through each pair that includes this party.
4. `mpc-party reseal -config party.json -destroy-label qv-share-wrap -confirm-restarted` removes the old key from the token. It refuses while the configuration still seals under it, while any share is sealed under it, while a reseal is unfinished, and without `-confirm-restarted`. Destroying the key is for good: do it after the step-3 checks, and after you have decided that you do not need a restart under the old key as a rollback.
5. New generations (every refresh) are sealed under the new key from the restart on.

**A resumed re-seal never overwrites a newer file.** Before the marker is written the command records the hash of every live file a staged file will replace; a resumed run moves a staged file only over a live file that still has that hash. A party that started between the runs, discarded an undecided refresh candidate and wrote a newer share at the same generation number keeps it: the staged copy is dropped and reported (`NOT moved`), and a new run moves what is left. `migrate-seal` shares the same move code and the same hole existed there (the staged `state.json` of an old run could replace a newer one); it now refuses, before moving anything, when a live file changed after its marker was written, and tells you to restore the snapshot and run it again.

A backup (`mpc-party backup`) does not depend on the wrap key: it is encrypted to the recovery key. Restoring a party into a token that has only the new key works as before.

**Attested mode.** There the shares are sealed under data keys that the attestation broker releases, one per keyset and generation plus one for local state, each wrapped under the party's key in the **broker's** HSM (`qv-attest-wrap-<party>`). Two things follow. A refresh already replaces the data key of a keyset (a new generation gets a new data key). The wrapping key itself cannot be replaced today: the wrapped blobs do not name their key and the broker has no call that re-wraps a blob under another key, so there is nothing for an operator to run. **What the broker would need (for the lead; the broker was not changed):** a key id in the wrapped blob, more than one wrapping key per party in its HSM, a `rewrap` call (the evidence-checked caller sends the blob, the broker unwraps and wraps under the new key inside the HSM session and returns it), a tool in the party that rewraps `local.key.json` and every generation file's wrapped key with it, and a destroy of the old wrapping key after every blob is rewrapped. With a cloud key service (the KMS adapter, task T7) the service's own key rotation covers this and the party only needs to accept a key id. Until then the remedy for a wrapping key that may have been misused is a replacement of the keysets.

## What a hardware key would need

Signing on a token (a YubiKey, an HSM) instead of a file: the tool needs a signing backend that takes the 32-byte message `Message2` builds and returns an Ed25519 signature (PKCS#11 `CKM_EDDSA`, or a token that exposes Ed25519). The party side stays as it is: it only needs the public key. Not built; `sign` reads a key file today.

## Local drill

`make test-mpc` runs the whole ceremony against real parties (`e2e/partyadmin`) with a 2-of-3 admin set made at setup: DKG of all three schemes with two signers, refresh, a tampered refresh that freezes the keyset, unfreeze, and the refusals (one signer, a stranger, a reused file, a changed field, the old v1 form). It also changes the admin set with a party down and finishes it, and walks the replacement of the recovery key through its status. The same changes, the break-glass and the wrap key run against party processes in `mpc-party/e2e` (`TestAdminSet…`, `TestRecoveryKeyReplacementWithSigningInFlight`, `TestResealWrapKeyOnRealToken`).
