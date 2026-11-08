# E23-2 — mpc-party serves 2-of-3 keysets with a third party

The service now holds two kinds of keyset side by side. The old one is the 2-party HD keyset (A and B). The new one is a 2-of-3
threshold ECDSA keyset (A, B and C): any two of the three sign, one can be down, patched or replaced. The wrapper calls
(`TDKG`, `Sign`, `Refresh`, `SelfTest`, backup) come from E23-1; this task puts them behind the service. Custody does not use them yet
(E23-3).

## Who talks to whom

```
                gateway (caller certificate)
                   |             |
              [ A ] -------- [ B ] ......... Sign (2-of-3 only)
                |   \          |
                |    \         |
                |     +----- [ C ]
                +-----------/
   A dials B and C.  B dials C.  C dials nobody.
   Every arrow is its own mTLS link; each side pins the other's certificate.
```

- A has no peer listener, so it can never be made to follow a session. B listens for A. C listens for A and for B and tells them
  apart by the certificate they present (the two pin sets are separate; a certificate pinned for A is not accepted as B).
- Caller ports are separate listeners with their own pins. A serves everything; B serves `Health` and `Sign` of 2-of-3 keysets
  (it coordinates B+C signatures); C serves `Health` only.

## Signing

The gateway calls `Sign` on A or B with `key_id` = the keyset id. The coordinator tries its peers in a fixed order (A: B, then C;
B: C). A follower does every check **before** it answers ACK: the keyset exists and is the same generation, it is resolved, not
frozen, `expected_public_key` is its own key, and its **own cosigner** approves (B and C ask in every role; B as a coordinator asks
before it opens a session; A is the gateway's pinned caller and asks nobody). Because everything that can refuse comes before the
ACK, the coordinator can tell *peer not available before signing* from *failed during signing*:

| What happened | Next peer? |
|---|---|
| connect failed, no ACK in time, follower unresolved / other generation / cosigner down (`TRANSPORT`, `UNAVAILABLE` before the ACK) | yes |
| follower or its cosigner refused (`REFUSED`), keyset frozen (`FROZEN`), a limit | no, returned as is |
| anything after the ACK: stall, cut link, bad proof (`CRYPTOGRAPHIC`) | no; a cryptographic failure freezes |

The coordinator checks the signature against the keyset's public key (btcec, low-S), stores it under the job id and returns it. A
retry through the other coordinator can return a different signature over the same digest: harmless for a transaction at one nonce,
and the gateway's guards (one digest per job) still hold.

## Creating, refreshing, reconciling

A three-party session is three streams. A opens one to B and one to C with the same group id; B opens a link stream to C with that id;
C starts when both arrived and ACKs both. Protocol data of each pair flows on its own stream; all control (results, commit steps)
goes between A and each follower. DKG and Refresh end with the **three-way self-test** (every pair signs). Then:

```
B, C: store the candidate generation, tell A (prepared)
A: stores its candidate, records its DECISION durably, tells B and C to commit
B, C: switch, tell A (switched)      A: switches, tells B and C (confirm)      everybody deletes the old generation
```

A crash at any step is repaired by **reconciliation**, driven by A, with the same rules as for two parties over three states:
a recorded decision is finished on every member; with none, candidates are dropped; members on different generations or a member with
no state mean a stale restore and are refused with a message that names the member and the generation to restore. After the plan
all three run the self-test; only then are older generations deleted. A starts it after a restart and whenever its link to B or C
comes back. `planReconcileT` is a pure function with a table test; the crash matrix kills B and C (and A) at every step.

## Freeze

A cryptographic failure freezes the keyset on both members of the session (durable). The coordinator tells the third member with a
freeze notice if it has a link to it. A member that was not told learns it later: a frozen member refuses every session with
`FROZEN`, a coordinator that hears `FROZEN` freezes too and passes it on, and reconciliation carries the flag. `Unfreeze` is a
session with B and C: each verifies the operator signature against its own `admin_keys`; nothing is lifted unless all three accept.
The protocol aborts without blame, so the log says which member the failed message came in from (`session_peer`) and that this is not
proof of guilt.

## Backup

Each member exports its own share per generation to the offline recovery key (PVE of the member's one scalar, plus the share blob
with the scalar wiped), verified on export; `Health` shows `backup_generation` and `backup_stale` on every party. Losing one member:
restore it from a backup of the current generation, then refresh. Details: [runbook](../runbooks/mpc-backup-restore.md).

## Gaps and decisions for the lead

- **A member that is away or stale does not stop the other two.** This covers A restarting while one member is down, a member
  restored from an older backup, and a member that lost its state. The strict three-way reconciliation cannot succeed in those cases,
  and left as it is the keyset would answer `UNAVAILABLE` for as long as the member is gone, which is the availability 2-of-3 exists
  for. So when the three-way run fails because a link is down or a member is stale, A reconciles with each of the other two alone
  (`reconcilePairWith`), but only when that is safe without the third: both hold the same current generation, neither has a
  candidate, and A has recorded no commit decision. They prove the keyset with a signature between the two and serve. The keyset is
  marked partial: when the missing member's link comes up A reconciles all three (and retries slowly if that still reports a stale
  member, with an `ALERT`), so a returning member never serves unreconciled and a stale one stays out (unresolved, never signing). This
  goes beyond the letter of the spec ("reconciled across the three"); it is tested (`TestThresholdAbsentMemberDuringRestart`,
  `TestThresholdMixedGenerationsNeverSign`, `TestThresholdBackupRestoreLostMember`) and one function to remove if you disagree.
- **B and C restart while A is down:** they stay unresolved until A returns and reconciles them (they cannot sign meanwhile); not
  changed. A pairwise B+C reconcile would be the same idea with B as the driver; not built.
- B cannot tell A directly that it froze a keyset (no link); A learns at its next contact with B (tested).
- Grants: C's caller port serves no `Sign`: the gateway reaches C only through A or B.
