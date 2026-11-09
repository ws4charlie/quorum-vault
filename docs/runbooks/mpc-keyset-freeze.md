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

## 2-of-3 keysets (A, B and C)

Same meaning, three members, for both 2-of-3 schemes (ECDSA and Ed25519 keysets freeze, unfreeze and reconcile identically). A cryptographic failure in a session between two members freezes the keyset on **both of them**; the
coordinator (A, or B when B+C signed) then tells the third member with a freeze notice. If the third was down or has no link to the
coordinator (B cannot reach A, C reaches nobody), it learns it at its next contact: a frozen member answers every session with
`FROZEN`, the one that hears it freezes too, and A's reconciliation carries the flag, so after A restarts or reconnects all three
are frozen. Check `Health` on all three parties (`frozen`) before and after.

Log lines: `ALERT keyset frozen after a cryptographic failure` (`scheme: ecdsa-2of3`, `op`, `job_id`, `session_peer`),
`ALERT keyset frozen on notice from another member`, `ALERT keyset frozen: another member holds it frozen`.

**The protocol aborts without blame.** `session_peer` is the member on the other end of the failed session, that is where the failing
message came in. It is not proof that this member cheated: the cause may equally be your own member, the link, or the third member
that fed the peer. Investigate all three hosts, not only the named one. (A three-party DKG, Refresh or Reconcile has no single peer:
the field is empty.)

Which pair signs does not matter for the remedy: the choices are the same as above (Unfreeze, Refresh, restore one member). With one
share possibly exposed, treat it as a compromised member: restore that member on a clean host from a backup and **refresh**; the old
share becomes useless, the public key (and so the address) is unchanged.

**Unfreeze** needs the operator signature accepted by **all three** members, each verifying it against its own `admin_keys`; if one
member is down or refuses, nothing is lifted anywhere. Call `Unfreeze` on party A. Each member logs `AUDIT keyset unfrozen`.
