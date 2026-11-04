# P5b-3 — Signing through MPC, with party B as an independent gate

Before this task the gateway signed with an HSM key and the cb-mpc service (P5b-2) refused everything on party B
(`deny-all`). Now the gateway signs through two-party MPC, and **party B decides again, on its own, from its own config and
its own database**. The threat: an attacker owns party A's host and A's certificate. A can ask B to sign; it must not be
able to get a signature for anything the approvers did not approve.

## What was built

| Piece | Where |
|---|---|
| Shared decision code (steps 1-5 + reservation) | [internal/gateway/decider.go](../../internal/gateway/decider.go) |
| Intent package (versioned, canonical) | [internal/gateway/intentpkg.go](../../internal/gateway/intentpkg.go) |
| Cosigner (B's decision service) | [internal/cosigner](../../internal/cosigner/cosigner.go), [cmd/qv-cosigner](../../cmd/qv-cosigner/main.go) |
| `signer.Signer` over party A | [internal/mpcsigner](../../internal/mpcsigner/mpcsigner.go) |
| Gateway wiring (`backend: "mpc"`, error mapping) | [config.go](../../internal/gateway/config.go), [mpcsigners.go](../../internal/gateway/mpcsigners.go), [gateway.go](../../internal/gateway/gateway.go) |
| Admin signatures, freeze, cosigner authorizer in the service | [admin.go](../../mpc-party/internal/server/admin.go), [freeze.go](../../mpc-party/internal/server/freeze.go), [cosigner.go](../../mpc-party/internal/server/cosigner.go) |
| Real-process tests | [e2e/mpcsign](../../e2e/mpcsign/) (`make test-mpc`) |

## Why B repeats the gateway's checks

```
business DB -> gateway -> party A ----(session)----> party B -> cosigner -> its own Postgres guard
 (untrusted)  checks 1-5   pinned caller            re-checks 1-5, from its own config
```
If B only trusted A, owning A would be enough. If the cosigner shared the gateway's database or config, owning those would be
enough. So the cosigner has its own approver keys, policy, chain verifier config and its own replay-guard database (a
different DSN), and counts caps and nonces from that. It runs in a separate process because the verifier needs go-ethereum,
which cannot link into `mpc-party` (two libsecp256k1 copies). It listens only on a unix socket with mode 0600; if it is down
or slow, B refuses (fail closed).

## One decision component, two modes

The gateway used to hold the checks inline. They are now `Decider.Decide` (intent, `TxVerifier`, approvals, policy, replay
guard, reserve the digest). The gateway uses mode `Gateway`; the cosigner uses mode `Cosigner`. The only difference: the
gateway stores the signature afterwards and treats a fresh unsigned reservation as "another worker is signing"; the cosigner
never sees the signature, so an identical repeat of an already reserved digest is a retry and is allowed. Anything else follows
the same rules (one intent, one nonce; a new digest for a known intent only as a same-nonce replacement). The gateway's
attack tests pass unchanged; the cosigner has a matching set.

## The intent package

A versioned JSON document (`qv-intentpkg-v1`): chain, partition, key ref, the intent bytes the approvers signed, the unsigned
payload, the digest, the approvals and the job id. The gateway builds it, party A forwards it opaquely in the OPEN frame, B
hands it to the cosigner. The cosigner checks that the job id and digest in the package are the ones B was asked to sign.

## The key that is judged is the key that signs

Review finding from P5b-2: B only compared the expected public key `if` it was present. A rogue A could omit it. Now B refuses
a Sign without an expected key before any message, passes that key to the cosigner (which requires the transaction's sender to
be that key's address), and after ACK derives the key itself: if the result differs from the expected key it aborts before any
signing message.

## Admin operations and freeze

`DKG`, `Refresh` and `Unfreeze` carry an operator's Ed25519 signature over `(op, keyset, timestamp)`. Both parties verify it with
their own list of admin keys, within a time window, once. A compromised A cannot start them.

A cryptographic failure (tampering, a failed proof, a failed self-test) freezes the keyset on the party that saw it and, via the
FIN frame, on the other. A frozen keyset refuses Sign, Derive and Refresh until an operator signature lifts it. The freeze is a
file on each party: it survives restart.

## What the gateway does with each error

| Service error | Gateway |
|---|---|
| `TRANSPORT`, `LIMIT`, `UNAVAILABLE` (cosigner socket down or slow, its database down, party B down) | **never finishes the job**: bounded retry inside `sign_timeout`, then `OutcomeRetry`; the job stays `signing` and is reclaimed when its lease ends, for as long as the outage lasts |
| `REFUSED` (A's or B's authorizer decided no) | job `rejected` with the reason, so the workflow cancels the nonce |
| `CRYPTOGRAPHIC`, `FROZEN`, `INTERNAL` | job `failed` and an `ALERT` log line |

Why availability must not finish the job: a rejected or failed job sends the withdrawal to the cancel path, which needs the same
cosigner and party B. During an outage the cancel fails too and the withdrawal is parked for an operator. A two-minute restart
would park everything in flight. Fail closed is unchanged (nothing is signed); only the outcome differs.

The cosigner's answer keeps *decision* and *outage* in separate fields (`allow`/`reason` versus `unavailable`), so nobody
matches on text: a guard-database failure or a deadline is `unavailable`; a policy refusal is not.

**How long can a job wait?** The workflow polls `sign_jobs` while the status is pending or signing, so it waits as long as the
gateway keeps the job in `signing`. The approval's `not_after` is checked only the first time a party sees an intent (the
gateway, and the cosigner): if the cosigner first sees the intent after `not_after` it refuses `intent_expired`, which is a real
refusal and goes through the normal cancel path. A job whose intent the cosigner already reserved keeps its reservation and is
re-signed after `sign_timeout` without a new expiry check. Nothing is voided or cancelled without going through the cancel path.

One `ALERT signer unavailable` is logged per chain per outage, and `signer available again: signing resumed` when it ends.

## Threats this does not cover

- A fully compromised A plus a compromised cosigner host.
- Denial of service: a malicious A can freeze a keyset or exhaust B's decision rate.
- A long cosigner outage leaves jobs waiting: monitor the ALERT line and the cosigner socket.

## Gotchas hit

- The guard schema was applied without a lock, so eight gateways started at once on an empty guard
  database fought over `CREATE TYPE` and seven died. Schema application now takes an advisory lock.
- Ed25519 admin signatures are deterministic, so two operations signed in the same second are the same bytes and the second is
  "already used". Tests move the timestamp by a second per call.
- The cosigner wire types live in the pure-Go `mpc-party/api` module, because `mpc-party/internal`
  cannot be imported from the root module.

## Quiz

1. Why does the cosigner have its own database instead of reading the gateway's?
2. Why can the `Decider` allow a repeat of a reserved digest in cosigner mode but not in gateway mode?
3. What did the P5b-2 review find about the expected public key, and how is it closed?
4. Which service error kinds make the gateway reject a job, which fail it, and which only make it wait?
5. A rogue A replays an approved intent at nonce+1. Who stops it?
6. Why is the cosigner a separate binary and not a library inside `mpc-party`?
7. What happens to a keyset when party B sees a cryptographic failure, and how does A learn?
8. What does an operator need to unfreeze, and who checks it?
9. How is "cosigner down" handled and why not as a refusal?
10. Why does the root module import `mpc-party/api` and not `mpc-party/internal/...`?

<details>
<summary>Answers</summary>

1. If an attacker can rewrite the gateway's database they could erase what was signed or reset caps; the cosigner's counts must not depend on it.
2. In gateway mode a fresh unsigned reservation means another worker is signing it; in cosigner mode nobody stores a signature, so the same digest again is a retry of the same signing, while a different digest follows the replay rules.
3. B checked the expected key only if present; B now refuses an empty one and aborts if its derived key differs, so the judged key is the signing key.
4. `REFUSED` rejects (nonce cancelled). `CRYPTOGRAPHIC`, `FROZEN`, `INTERNAL` fail with an ALERT. `TRANSPORT`, `LIMIT`, `UNAVAILABLE` only make the job wait and be retried.
5. B's cosigner, from its own guard: the intent was signed at nonce 0, so nonce+1 is `replay_nonce_changed`.
6. It needs go-ethereum's chain verifier, which cannot link with cb-mpc's secp256k1.
7. It freezes the keyset durably and sends a failing FIN with the kind; A freezes its side on receiving it.
8. An Ed25519 signature by a configured admin key over (unfreeze, keyset, timestamp); both parties check it against their own admin keys.
9. B does not sign (fail closed) and reports `UNAVAILABLE`; the gateway leaves the job waiting. A refusal would reject the job and the cancel would fail for the same reason, parking the withdrawal.
10. Go's `internal` rule: only code under `mpc-party/` may import it, and it must stay free of go-ethereum/cgo concerns in the other direction.

</details>
