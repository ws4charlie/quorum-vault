# Runbook: a key ceremony with `qv-party-admin` (DKG, refresh, freeze, unfreeze)

The parties' admin calls (`DKG`, `Refresh`, `Unfreeze`) need the signatures of **M of the N admin keys** (`admin_threshold` of `admin_keys`). All signatures cover **one request file** that names everything the call does: the operation, the keyset, for a DKG the scheme and the curve, the deployment (`admin_domain`), the time it was made and expires, and a random nonce. Every party rebuilds what was signed from the call it receives and checks it against its own `admin_keys`, so a changed field, another keyset or another operation fails. Each party accepts a request **once**, also across a restart.

`qv-party-admin` splits the work so that no signing key ever enters a cluster:

| Step | Command | Where | Holds |
|---|---|---|---|
| request | `qv-party-admin request -op dkg\|refresh\|unfreeze -keyset ID [-scheme … -curve …] [-domain NAME] [-valid-for 1h] -out req.json` | any admin's machine | nothing secret |
| sign (M admins, one after the other) | `qv-party-admin sign -key admin.key -in req.json` | each admin's own machine | that admin's signing key |
| check | `qv-party-admin verify -in req.json -config partyA.json -config partyB.json …` (or `-admin-key HEX … -threshold M`) | anyone | nothing |
| send | `qv-party-admin dkg\|refresh\|unfreeze -auth req.json -party A=HOST:PORT@PIN …` | a Job in party A's cluster (chart `operator.job`), or a labelled bastion pod | a caller certificate, the signed file |
| status | `qv-party-admin status -party … [-keyset ID]` | a Job in each party's cluster | a caller certificate |

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
| `no longer accepts the v1 authorization format` | an old v1 file reached a party with `admin_threshold` set | use `request` and `sign -in`; see the roll-over below |
| `THE PARTIES DISAGREE` | generation, frozen flag, public key or presence differs, or a party did not answer | stop; use [mpc-failures.md](mpc-failures.md); a half-done refresh or DKG is reconciled by the parties on restart, then check again |
| `-auth is required` | `send` runs without a file | get the file from the admins; the Job holds no key and cannot make one |

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

## Adding or removing an admin key

`admin_keys` and `admin_threshold` are party configuration (chart `adminKeys`, `adminThreshold`). To **add** a key: add its public key on all three parties (config change and restart each), then it can sign. To **remove** one: remove it on all three; files signed by it are then refused as a whole (`not a configured admin key`): make a new request without it. Keep `adminThreshold` between 1 and the number of distinct keys, and at most 32 (one authorization carries at most 32 signatures; a party refuses to start otherwise, and the chart and `qv-party-admin` refuse such a value). More than 32 keys are fine while the threshold stays within 32. Do the three changes in one maintenance window: a party that still lists a removed key still accepts it. Rotating the keys in a controlled, audited way is a separate piece of work (K7).

## What a hardware key would need

Signing on a token (a YubiKey, an HSM) instead of a file: the tool needs a signing backend that takes the 32-byte message `Message2` builds and returns an Ed25519 signature (PKCS#11 `CKM_EDDSA`, or a token that exposes Ed25519). The party side stays as it is: it only needs the public key. Not built; `sign` reads a key file today.

## Local drill

`make test-mpc` runs the whole ceremony against real parties (`e2e/partyadmin`) with a 2-of-3 admin set made at setup: DKG of all three schemes with two signers, refresh, a tampered refresh that freezes the keyset, unfreeze, and the refusals (one signer, a stranger, a reused file, a changed field, the old v1 form).
