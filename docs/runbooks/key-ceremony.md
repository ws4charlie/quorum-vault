# Runbook: a key ceremony with `qv-party-admin` (DKG, refresh, freeze, unfreeze)

The parties' admin calls (`DKG`, `Refresh`, `Unfreeze`) each need a signature by an operator's Ed25519 key. Every party checks it against its own `admin_keys`. The signature covers the operation, the keyset and the time; it is valid for the parties' own window (`adminMaxAgeSeconds`, **300 s**), and each party accepts it **once**.

`qv-party-admin` splits the work so that no signing key ever enters a cluster:

| Step | Command | Where | Holds |
|---|---|---|---|
| sign | `qv-party-admin sign -key operator.key -op dkg\|refresh\|unfreeze -keyset ID -out auth.json` | the operator's own machine | the operator's signing key |
| send | `qv-party-admin dkg\|refresh\|unfreeze -auth auth.json -party A=HOST:PORT@PIN …` | a Job in party A's cluster (chart `operator.job`), or a labelled bastion pod | a caller certificate, the signed file |
| status | `qv-party-admin status -party … [-keyset ID]` | a Job in each party's cluster | a caller certificate |

There is **no admin call that freezes**. A party freezes a keyset itself after a cryptographic failure ([mpc-keyset-freeze.md](mpc-keyset-freeze.md)). Freezing on purpose means stopping the keyset's signing path (the gateway route) and, if a host is lost, taking that party out.

## The 300-second rule

`sign` prints when the file expires. The window runs from signing to the moment party A and the others check it, so:

- Have everything else ready first: the Job values, the caller-certificate Secret, the image already on the node (run a `status` Job first: it pulls the image and proves the path).
- Sign, create the ConfigMap, start the Job: one paste, no waiting for people. The tool refuses a file older than the window **before** calling, and says so.
- The parties also accept a time up to 300 s **ahead**, so clock skew between the operator's machine and the cluster of up to 5 minutes is tolerated; more than that, fix the clock. Do not widen `adminMaxAgeSeconds` to make a slow process fit: make the process faster.
- A used or failed call may have consumed the file. After any failure, check `status`, then sign a new file. Never reuse one.
- DKG and refresh themselves can take a minute or more; the window applies to the **start** of the call only.

## Who is in the room

Two people at least: an **operator** (holds the signing key, runs `sign`) and a **cluster operator** of party A (creates the ConfigMap and Job; has no signing key). A third person (a party B or C cluster operator) runs the `status` Job in their cluster before and after, so each party's own view is checked by someone who does not control party A. No one has admin on two party clusters ([qv-party chart README](../../deploy/helm/qv-party/README.md), "Operators").

## Before (every ceremony)

1. All parties up: run `status` as a Job in each party's cluster (`operator.job.command=status`). Every party shows its links reachable, the same generation and frozen flag for the keyset, and the same public key for a 2-of-3 keyset. The tool exits non-zero and prints `THE PARTIES DISAGREE` when they do not: stop and find out why.
2. The operator's public key is in every party's `adminKeys` (the `public_key` in the signed file is what the parties compare). Check it against the list the parties were configured with, not against the file.
3. A caller certificate for the Job: made for this ceremony, pinned in every party's `callerPins` it will talk to, deleted afterwards. Its Secret has `tls.crt` and `tls.key`.
4. `partyPin`: the pin of **party A's** certificate (SHA-256 of its public key), from the certificate catalogue, not from the party. The Job refuses any other server.
5. Backups: a refresh and a DKG change what a backup must hold ([mpc-backup-restore.md](mpc-backup-restore.md)). Know who exports the new generation afterwards.

## DKG (a new keyset)

1. Choose the keyset ID (letters, digits, `.`, `_`, `-`; up to 64) and the scheme: `ecdsa-2of3` (EVM), `ed25519-2of3` (Solana) or `hd` with `-curve` (two-party HD, Bitcoin). All three parties must be online for 2-of-3.
2. On the operator's machine, immediately before the Job: `qv-party-admin sign -key operator.key -op dkg -keyset hot-7 -out auth.json`.
3. In party A's cluster: `kubectl -n qv create configmap dkg-auth --from-file=auth.json`, then install the Job: `helm upgrade --install … --set operator.job.enabled=true --set operator.job.command=dkg --set operator.job.keysetId=hot-7 --set operator.job.scheme=ecdsa-2of3 --set operator.job.authConfigMap=dkg-auth --set operator.job.callerCertSecret=… --set operator.job.partyPin=… --set operator.job.name=dkg-hot-7`. Read `kubectl logs job/…`.
4. Output: `OK dkg: keyset ID generation 1` and `root_public_key`, preceded by the status of party A. It refuses if the keyset already exists.
5. **After:** the `status` Jobs of B and C show the keyset, generation 1, not frozen, the same public key as the output. Write the public key into the change record. Then follow the caller's runbook (for a hot-key replacement: [key-replacement.md](key-replacement.md), step 2).

## Refresh

Same four steps with `-op refresh`; the keyset must exist, be unfrozen and be at the same generation on every party. All parties must be online. The result is `OK refresh: keyset ID generation N+1`; the public key must be unchanged. The parties run their own self-test and keep the old shares unless it passed. After: every party shows generation N+1; export the new generation's backup.

## Freeze, and unfreeze

A frozen keyset refuses signing and refresh. **Do not unfreeze until [mpc-keyset-freeze.md](mpc-keyset-freeze.md) says the cause is understood**; unfreezing a compromised party's keyset gives it more tries. To unfreeze: `-op unfreeze`, same steps. Both parties must be reachable; the tool refuses a keyset that is not frozen. After: `OK unfreeze … not frozen on any of the N parties`, and the `status` Jobs of the other parties agree. Jobs the gateway parked stay parked until an operator clears them.

## When it fails

| Output | Meaning | Do |
|---|---|---|
| `outside the 300s the parties accept` | the file is too old (local check, nothing was sent) | sign a new one and send at once; speed up the steps |
| `not a configured admin key` | the operator key is not in that party's `adminKeys` | fix the party's config through its change process; do not widen anything on the spot |
| `signature already used` | the file was already accepted by that party | check `status`; sign a new file only if the operation did not happen |
| `THE PARTIES DISAGREE` | generation, frozen flag, public key or presence differs, or a party did not answer | stop; use [mpc-failures.md](mpc-failures.md); a half-done refresh or DKG is reconciled by the parties on restart, then check again |
| `-auth is required` | `send` runs without a file | get the file from the operator; the Job holds no key and cannot make one |

## One operator key: the risk

The parties accept **one** signature from any key in `admin_keys`. Whoever holds one operator key (and a caller certificate) can run a DKG, a refresh or an unfreeze, within 300 s of signing; a stolen key can unfreeze a keyset that was frozen for a reason. Keep each key on its own hardware token, in the hands of one named person, and keep `admin_keys` short. A **quorum** (two operators for an unfreeze, say) is a protocol change: the parties would verify an `AdminAuth` list and a threshold, and each signature would need its own replay record. It is not built; until it is, the second person in the room is a procedure, not a check the parties enforce.

## Local drill

`make test-mpc` runs the whole ceremony against real parties (`e2e/partyadmin`): DKG of all three schemes, refresh, a tampered refresh that freezes the keyset, unfreeze, and the refusals.
