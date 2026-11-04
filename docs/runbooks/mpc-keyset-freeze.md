# Runbook: a frozen MPC keyset

## What a freeze means

A **cryptographic** failure (a zero-knowledge proof did not verify, a message could not be parsed, a final signature check
failed, a C++ assertion fired while processing the peer's messages, a self-test failed) freezes the keyset **on both parties**:
the one that saw it freezes locally and tells the other in the closing frame. A frozen keyset refuses `Sign`, `Derive` and
`Refresh` with the error kind `FROZEN`; the gateway fails the job and logs `ALERT`. The freeze is a file under `data_dir/freeze`
and survives restarts. Only an operator signature lifts it. Nothing else is damaged: no share is deleted and no signature was
produced for the failed session.

Why: a failed check can mean a malicious or corrupted peer, a corrupted share, or an attack on the link. Continuing to sign
would give a hostile peer more tries. Availability problems (a party down, a timeout, the cosigner unreachable, a limit) are
**not** freezes: they leave jobs waiting and recover on their own.

## Alerts

`ALERT keyset frozen after a cryptographic failure` (mpc-party A and B), `ALERT signer failure` / `ALERT signer unavailable`
(gateway), `ALERT keyset cannot be reconciled with the peer` (a stale restore or lost state).

## Investigate (before anything else)

1. Which keyset, which operation, which job: the freeze log line has `keyset_id`, `op`, `job_id`, `peer_reported` (true: the
   other party found it) and the message.
2. Both parties' logs around that time. Is the network path between A and B under your control (mTLS, pinned certificates)? A
   byte flipped inside TLS is not possible; a flipped byte at the application layer means a compromised proxy or a compromised
   party.
3. Is one party compromised? Check the host (integrity, unexpected processes, recent access), the HSM audit log, and whether the
   cosigner refused anything unusual (`cosigner decision` lines with `allow:false`).
4. Was it a crash or restore? Those do not freeze (they reconcile). A freeze right after a restore points to a bad backup.

## Decide: Unfreeze, Refresh, or restore

| Situation | Action |
|---|---|
| Transient fault proven harmless (e.g. a known bug, a corrupted message on a test proxy) and both hosts are trusted | `Unfreeze`, then watch |
| A party's share may be exposed or a party's host is suspect | **Do not unfreeze.** Move funds with the cold tier, retire the key (new DKG, new addresses). A refresh does not help a share that was already stolen together with the other (see below) |
| The hosts are trusted but one share is corrupted or lost | restore that party from backup (`mpc-party-backup-restore.md`), which brings it back on the current generation |
| An attacker may have had ONE share for a limited time, and both hosts are now clean | `Refresh` (new shares, same public key): the old share becomes useless. Needs an unfrozen keyset: unfreeze first, refresh immediately, take new backups |

A refresh protects against an attacker who held one share for a while and no longer does. It does not help against an attacker
who obtained both shares (or one share plus a backup of the other plus the recovery key).

## Unfreeze

An operator signs `(unfreeze, keyset id, timestamp)` with an Ed25519 admin key (`api/admin`); both parties verify it against
their own `admin_keys`, within `admin_max_age_seconds`, once. Call `Unfreeze` on party A; A asks B, B verifies the signature
itself. Both log `AUDIT keyset unfrozen` with the admin key. Run a signing self-test through a non-production key first if in
doubt, then watch the next signs.
