# P3a study guide: the signing gateway and the outbox relay

Code: `internal/gateway/`, `internal/signjob/queue.go`, `internal/outbox/relay.go`, `cmd/qv-gateway`, `cmd/qv-relay`. Role: `migrations/0004_gateway_role.sql`.

## 1. Threat model

Assume an attacker has full write access to the business database (SQL injection, a stolen service password, a malicious operator). They can insert, edit and delete any row: jobs, approvals, history, even a table of "approver keys". They cannot touch the signing zone: the gateway host, its config file, its HSM and its own database.

The goal is one sentence: **no transaction is signed that was not approved**. So the gateway treats a `sign_jobs` row as a claim to examine, never as an instruction.

What the attacker can still do, and what bounds it:

| Attacker holds | Can do | Bounded by |
|---|---|---|
| Business DB only | Nothing is signed except what valid approvals cover | Everything below |
| + the automated approver key (stolen from the business zone) | Sign small withdrawals | Per-transaction cap, rolling 24-hour cap |
| + sweep job write access | Trigger sweeps to the configured destination | Sweep rate limit; destination pinned in the verifier |
| + `qv_gateway` DB credentials | Read and update `sign_jobs` | Cannot reach any other table; cannot sign |

Not defended: a compromised gateway host or config, a threshold of stolen human approver keys, and a wrong config. Those are the signing zone's own security.

## 2. The decision order, and why

For each claimed job the gateway runs six steps. The first failing step rejects, with one reason code per step (`reject_reason` is `<code>: <detail>`).

| # | Step | Code | Why here |
|---|---|---|---|
| 1 | Parse the intent; its chain and partition equal the job's | `intent_invalid` | Everything later reads the intent, so it must be well formed first |
| 2 | `TxVerifier.Verify`: digest, destination, asset, amount, fee cap | `tx_mismatch` | Binds the bytes that will be signed to the readable intent. After this, the intent is what the transaction does |
| 3 | Ed25519 approvals over `Intent.Hash()`, configured and enabled actors only, each actor once | `approval_invalid` | Approvals prove people agreed to the intent. They are meaningless until step 2 says the tx is that intent |
| 4 | Policy: per-transaction cap, rolling cap, approvals required for the amount, sweep and cancel rate | `policy_*` | Needs a trusted amount (step 2) and a count of valid approvers (step 3) |
| 5 | Replay guard | `replay_*` | Last check before signing, under the guard's lock, so the answer it gives is still true when we sign |
| 6 | Reserve the digest, sign outside the lock, verify locally, store, then release | `signer failed` (job `failed`) | Nothing is signed until every refusal had its chance |

Steps 4 and 5 and the reservation of step 6 run in one guard transaction under a per-chain lock. The signer call runs after it commits (section 3, "Reserve, sign, finish").

Cheap, local, stateless checks come first; checks that read state come later; the one check that must not race (5) runs together with the signing under a lock.

Approvals expire. `Intent.NotAfter` (Unix seconds) is part of what approvers sign. A first-time withdrawal whose `NotAfter` is zero, already past, or further ahead than `max_intent_age` (config, default 24h) is refused with `intent_expired`. Without this, an approved withdrawal that was cancelled before signing (so the guard never saw it) could be re-enqueued by an attacker later and signed, though the customer's hold was already released. A known intent (already in the guard) skips the check, because replacing a stuck transaction must work after expiry; it still cannot move to another nonce.

Intent rules: a withdrawal needs at least one valid approval and the number its amount tier asks for. A sweep needs no approval but must pass the rate limit, and the verifier pins its destination to the signing-zone config. A cancel needs no approval, passes a rate limit, and must be sent from a hot address the gateway owns.

## 3. Why the replay guard lives in the signing zone

Consider the double-withdrawal attack. A withdrawal is approved and signed at nonce 7. The attacker copies the job under a new job ID with nonce 8. Intent, destination, amount and approvals are all valid: approvals sign the **intent**, and the intent does not contain the nonce. Steps 1 to 4 pass. Only a memory of "this intent was already signed" stops it.

That memory cannot be the business database, because the attacker writes it. If it were, they would delete the record and replay. So the gateway keeps it in a separate database (`-guard-dsn`), schema `internal/gateway/store.sql`, which the business-side role cannot reach (and which the gateway's `qv_gateway` role has no way to touch either).

The guard records, before a signature is released: intent ID and hash, kind, asset, amount, sender, nonce, digest, fees, signature, time. Its rules:

- Same intent, same digest: return the stored signature. Never sign twice. This is also how a crashed gateway recovers.
- Same intent, new digest: only at the **same nonce** with fees that did not drop and at least one that rose. That is a replacement. A different nonce is the double-withdrawal attack (`replay_nonce_changed`).
- Same intent ID, different hash: `replay_intent_conflict`.
- One intent per `(chain, sender, nonce)`. A cancel may take a nonce from a pending transaction; after that no withdrawal can sign there (`replay_nonce_cancelled`). A cancel is how a stuck nonce is released.
- Caps and rate limits are sums over the guard's own rows. Deleting `sign_jobs` history, or editing timestamps there, changes nothing. A replacement is counted once, not per signature.

### Reserve, sign, finish

Signing is slow (an HSM call now, MPC rounds later). Holding the chain lock and a transaction during it would make one hung signer stop every signature on the chain, and cap throughput at 1 / sign-latency. So a decision has three phases:

1. **Reserve** (guard transaction, per-chain advisory lock): steps 4 and 5, then write the intent, the nonce claim and a `signed_digests` row with `signature` NULL and `reserved_at`. Commit. Caps and the nonce are now taken.
2. **Sign** (no lock, no transaction), under `sign_timeout` (default 30s); verify the signature locally. A signer that ignores its context is abandoned and the job fails.
3. **Finish**: `UPDATE ... SET signature WHERE digest=$1 AND signature IS NULL`, then read the row back and release only that stored value. If two signatures race, the first stored wins; the other is discarded and never leaves the zone.

A repeat of a digest finds: a signature, so return it; a reservation younger than `sign_timeout`, so another worker is signing and the result is `retry` (the job stays with its lease); an older reservation, so the signer died, and the same digest is signed again. If the signer fails, the reservation stays and the job is `failed`: its amount still counts toward the caps and its nonce stays taken, until a cancel releases the nonce. Replacement fee comparison includes reserved rows, so a replacement cannot undercut an unsigned reservation. Measured: 48 jobs, 8 workers, 100 ms signer, one chain: about 52 signatures/s (ideal 80/s).

Two gateway instances: the reserve step is serialized by the lock. The second instance waits, then sees the first one's reservation and retries, or the signature and returns it. Unique keys on the intent ID, the digest and the nonce claim are a second barrier if someone bypasses the lock. The test calls two instances concurrently on one job and counts exactly one signer call.

Approver keys must be distinct: config is refused if two actors share a public key, so one key cannot satisfy a 2-of-N tier.

## 4. Queue and crash safety

`sign_jobs` is a work queue: `Enqueue` runs in the caller's transaction, so a job exists iff the business change committed. `Claim` is one statement, `UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1)`: concurrent workers never get the same job, and the oldest goes first. It also takes `signing` jobs whose lease expired. `Complete`, `Reject` and `Fail` only succeed for the worker named in `locked_by`; a slow worker that lost its job cannot finish it.

Crash cases, both tested:

- Crash after the guard committed but before `Complete`: the lease expires, another claim reaches step 5, finds the digest, returns the stored signature. No second signing.
- Crash before the guard committed: nothing was recorded, the reclaim signs once.

A policy refusal marks the job `rejected`; a signer error marks it `failed`; a transient error (database down) leaves the job to its lease.

## 5. The database role

`qv_gateway` has `SELECT` and `UPDATE` on `sign_jobs` and no other privilege. Roles are cluster-global, so the migration creates it only if missing and survives a concurrent create. It is `NOLOGIN` in the migration; an operator grants `LOGIN` and a password outside the repo. The test switches to the role and checks that other tables are unreadable.

## 6. Outbox relay: at-least-once

Business code writes an event into `outbox` in the same transaction as the change. The relay then moves rows to Kafka:

1. In one transaction, claim unpublished rows in `seq` order with `FOR UPDATE SKIP LOCKED`.
2. Publish each to Kafka (franz-go, idempotent producer, acks from all in-sync replicas, key = the row's key), one at a time, waiting for the ack.
3. `UPDATE ... SET published_at` for the acknowledged rows, and commit.

Delivery is **at least once**. If the relay dies between step 2 and step 3, the rows stay unpublished and the next run sends them again. Exactly-once across a database and Kafka would need a shared transaction, which we do not have. So every record carries the event ID in header `id` (the same ID on a repeat) and consumers must ignore an ID they have seen.

Ordering: rows are published in `seq` order, and the batch stops at the first publish error, so a later event never overtakes an earlier one of the same key. Two relays running at once take different batches, so order holds inside a batch only; run one relay, or accept that. When Kafka is down the relay backs off (200 ms doubling to 10 s) and rows stay unpublished; nothing is dropped. The producer's idempotence protects against duplicates inside one producer session only; it does not replace the event ID.
