# P5b-4 — Sealing, durable refresh, backup and restore

Before this task the shares were sealed with a test key that sat next to them, a refresh stored the new shares with one write,
and a crash between party B's commit and party A's commit left the two parties on shares that do not work together. Now a
stolen disk yields nothing, a crash at any step converges to one working generation, and a lost party is restored by a written
procedure that is drilled.

## What was built

| Piece | Where |
|---|---|
| PKCS#11 sealer (AES-256-GCM inside the token) | [sealer_pkcs11.go](../../mpc-party/internal/server/sealer_pkcs11.go) |
| Insecure test sealer, only with `-tags devauth` | [sealer_insecure.go](../../mpc-party/internal/server/sealer_insecure.go) |
| Generations, candidate, decision | [store.go](../../mpc-party/internal/server/store.go) |
| Two-phase commit, party A | `commitA` in [coord.go](../../mpc-party/internal/server/coord.go) |
| Two-phase commit, party B | [peer.go](../../mpc-party/internal/server/peer.go) |
| Reconciliation after a restart or restore | [reconcile.go](../../mpc-party/internal/server/reconcile.go) |
| Crash failpoints (dev builds only) | [failpoint.go](../../mpc-party/internal/server/failpoint.go), [failpoint_dev.go](../../mpc-party/internal/server/failpoint_dev.go) |
| Backup format and crypto | [internal/backup](../../mpc-party/internal/backup/backup.go) |
| CLI `mpc-party backup ...` | [cmd/mpc-party/backup.go](../../mpc-party/cmd/mpc-party/backup.go) |
| Runbooks | [backup-restore](../runbooks/mpc-backup-restore.md), [freeze](../runbooks/mpc-keyset-freeze.md) |
| Drill | [restore-drill.sh](../../mpc-party/scripts/restore-drill.sh) |

## Sealing

Each party has its own HSM token (A: `qv-party-1`, B: `qv-party-2`) and a non-exportable AES-256 key in it. Sealing runs
`CKM_AES_GCM` inside the token and returns the envelope `{v, iv, ct}` of the root module's `internal/mpc/seal` (repeated here:
this module may not import the root). The **associated data** binds `role | keyset id | generation | algorithm`, so a blob moved
to the other party, another keyset or another generation fails GCM authentication. The PIN comes from an environment variable or a
file that only its owner can read; it is never in the JSON config or an error message.

A wrong PIN, a missing token or a missing library stops the process at start with a clear message. An HSM error while unsealing
at run time is `UNAVAILABLE` (jobs wait, the process lives); a blob that does not authenticate is an internal error (corruption),
not an outage.

The insecure sealer is behind `-tags devauth`, the same tag as `dev-allow-all`. A production binary does not contain the code
(the test looks for the symbol with `go tool nm`) and refuses the sealer type.

## Generations and the durable two-phase commit

Every keyset has a generation number that only grows. The store keeps the **current** generation and, during a DKG or refresh,
one **candidate**. Party A also records a durable **decision**.

```
run protocol + SelfTest on the candidate (both)
B stores the candidate durably        --prepared-->  A
A stores the candidate durably
A records its DECISION durably (point of no return)
A  --commit-->  B        B makes the candidate current     --switched-->  A
A makes the candidate current         A --confirm--> B
both delete the old generation (only now)
```
Old shares exist until both parties confirmed. The failpoints crash a party between every pair of steps; see the crash matrix
below.

**Reconciliation.** After a crash, a restart or a restore, a party cannot know what the other did. So every keyset starts
**unresolved** and answers `UNAVAILABLE`; party A reconciles it with B (and again whenever the connection to B comes back):
- A has a decision for generation g: finish the commit (whoever still has g as candidate makes it current).
- no decision: nothing was committed anywhere; both drop their candidate. (B only switches on A's commit message, which follows
  A's durable decision.)
- different current generations without a decision: one party is stale (a restore from an old backup): refuse, naming the party and
  the generation to restore.
Then both run a SelfTest on the resulting generation. Only after it passed are old generations deleted and the keyset served.

**Sign during a refresh.** A session holds the keyset's gate shared; the commit window (from A's decision to its switch) holds it
exclusively, so no session runs while the parties switch. A new Sign waits briefly. The Open frame carries the generation; B refuses
a different one with `UNAVAILABLE`, never as a cryptographic failure. **Concurrent Refresh** of one keyset is refused (`LIMIT`).

## Backup and restore

`mpc-party backup`:
1. `gen-recovery-key` (offline): a PVE key pair and an RSA-3072 pair. The private file is mode 0400 and never touches a party host.
2. `export` (on the party): unseals the current generation through the HSM, takes the share apart (`Split`), PVE-encrypts the
   two scalars to the recovery key, encrypts the rest of the blob with AES-GCM under a key wrapped by RSA-OAEP to the recovery
   key (for party A the rest still holds the Paillier private key), and writes a versioned file with keyset id, generation, role,
   algorithm, root public key and time. It then **verifies the file it wrote** and records the verified generation.
3. `verify`: public data only (the PVE proof against the public share points, bound by label to keyset, generation, role).
4. `restore` (offline): decrypts, verifies the PVE again, checks the shares against the recorded public points and the root key,
   and writes a keyset sealed for the **target party's** token into an empty data directory.

After every refresh the service logs that backups are stale and `Health` reports per keyset the last verified backup generation.
A restored party rejoins through reconciliation and a SelfTest; a backup older than the peer is refused.

## Gotchas hit

- A PKCS#11 module can be initialized once per process, and a second login to a slot that is already logged in does not re-check the PIN.
  Sealers share one module context; the wrong-PIN test is a separate process.
- A gRPC channel goes idle after the peer drops and only reconnects on the next RPC, so party A did not notice that B had restarted.
  The reconcile loop keeps the channel connecting and reconciles every keyset after a reconnect.
- An aborted DKG leaves a candidate-only state on the party that stored it; it is dropped on abort and by reconciliation, and
  `Health` does not list it.
- Ed25519 admin signatures are deterministic: tests move the timestamp by a second per call.
- B's busy flag is held until its handler returns; A waits for the stream to end before it frees its own, or the next refresh would
  be refused as "already running".

## Quiz

1. What does the associated data of a sealed keyset bind, and what attack does that stop?
2. Why does party B store the candidate before it says "prepared", and A record its decision before it tells B to commit?
3. A crashes right after recording its decision. What does reconciliation do, and why is that safe?
4. A crashes right before recording it. What happens to B's candidate?
5. Why is the unfinished DKG candidate not listed by `Health`?
6. What stops a Sign from running while the parties switch generation?
7. Why can the backup of party A not be just the PVE ciphertext?
8. What happens if party B is restored from a backup of generation 3 while A is on generation 5?
9. Where must the recovery private key never be, and what do two backups plus that key equal?
10. How does a production build differ from a dev build with respect to sealing and testing hooks?

<details>
<summary>Answers</summary>

1. Role, keyset id, generation and algorithm. A blob copied to the other party, another keyset or an older/newer generation fails to open.
2. If B said "prepared" without a durable candidate, A could decide to commit and B could not follow after a crash. If A told B to commit before its own decision was durable, a crash of A would forget a commit that B already made.
3. It finishes the commit: both make the decided generation current (whoever still has it as a candidate), run a SelfTest, then delete the old one. Safe because B stored the candidate before A decided.
4. Nothing was committed anywhere (B only switches on A's message after the decision): A drops its candidate and tells B to drop its own.
5. It is not a keyset yet: it has no current generation and may be dropped by an abort.
6. The keyset gate: sessions hold it shared, the commit window holds it exclusively on each party, and the Open frame names the generation so a mismatch is `UNAVAILABLE` instead of a failed proof.
7. PVE carries only x mod q; after a refresh party A's exact share can be larger, and it is recovered from the Paillier ciphertext in the stripped blob, which also holds the Paillier private key.
8. It stays unresolved and answers `UNAVAILABLE`; the log says party B is older and which generation to restore from. Nothing is signed.
9. Never on a party host (offline, M-of-N cold ceremony). Both parties' backups of one generation plus that key equal the whole signing key.
10. A production build has only the PKCS#11 sealer and no failpoints and no dev authorizer; the dev build (`-tags devauth`) adds the insecure sealer, `dev-allow-all` and the crash failpoints.

</details>
