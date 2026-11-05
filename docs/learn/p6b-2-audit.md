# P6b-2 — Tamper-evident audit on /v2

Before this task the `/v2` path wrote three audit events, nothing read them, and a row of the outbox could be changed. After a
dispute we could not have shown who decided what. Now every decision is in a hash chain, and a change to the chain can be seen.

## Three chains

| Chain | Database | Written by | Why separate |
|---|---|---|---|
| core | business | one chainer in [qv-relay](../../cmd/qv-relay/main.go) | the record of what people and workflows asked for |
| gateway | its guard database | [Decider](../../internal/gateway/decider.go) and [Guard.Finish](../../internal/gateway/store.go) | it must record what it refused even if `qv-core` is down or lying |
| cosigner | its own guard database | the same code, in cosigner mode | party B's gate keeps its own record |

All three use [internal/audit](../../internal/audit/audit.go): `hash = SHA-256(prev_hash || canonical JSON of the entry)`, genesis
is 32 zero bytes, appends take one advisory lock so seq has no gaps.

## Core: outbox, then chainer

Business code calls `emit` ([service.go](../../internal/custody/service.go)); for the events in the `audited` list it also writes a
row to the outbox topic `qv.audit` **in the same transaction**. The audit entry therefore exists exactly when the change committed.

The [chainer](../../internal/auditchain/chainer.go) then, in one transaction: takes the advisory lock (or leaves if another holds
it), selects outbox rows with `chained_at IS NULL`, appends each to `audit_log` with `source_id` = the outbox id, and sets
`chained_at`. Points to remember:

- It selects "not chained", **not** "seq above the last one". A transaction that took a lower seq may commit after a higher one
  (test: `TestChainerPicksUpRowCommittedOutOfOrder`).
- A crash anywhere rolls the whole transaction back; the next run redoes it. `audit_log.source_id` is unique, so even a bug could
  not chain a row twice.
- Why not append inside the business transaction? Then every business transaction would wait for the one before it to release the
  chain head.
- [Migration 0011](../../migrations/0011_audit_chain.sql) makes outbox rows immutable (only `published_at` and `chained_at` change,
  and `chained_at` only once), so an event cannot be edited between the change and the chain.

## Gateway and cosigner: no signature without a record

[audit.go](../../internal/gateway/audit.go) records four things:

| Event | When | Where |
|---|---|---|
| `sign.allowed` | steps 1–5 passed | in the guard transaction that reserves the digest |
| `sign.replayed` | a stored signature is returned | in the guard transaction |
| `sign.completed` | the signature is stored (gateway) | in the same transaction as the update |
| `sign.refused` | a policy refusal, with code and detail | its own transaction, before the refusal is reported |

If any append fails the guard transaction rolls back: no reservation, the signer does not run, the job is retried (a refusal that
cannot be recorded is also a retry, and for the cosigner an `Unavailable` answer, which party B treats as no). Payloads hold job,
intent, kind, asset, amount, sender, nonce, digest, intent hash and the approver names. Never a signature or key.

## Anchors

[PublishHeads](../../internal/auditchain/anchors.go) polls the chain head every second and publishes `{source, seq, hash, at}` to
`qv.audit.heads` when it changes and at least once per interval. A failed publish is retried with the head of that moment, so a
Kafka outage delays anchors but never chaining or signing.

## What each kind of tampering looks like

The attacker can switch the triggers off.

| Tampering | Chain check | Anchors |
|---|---|---|
| change a row | fails at that seq | also fails |
| delete a row | fails at the next seq | also fails |
| cut off the tail | **valid** | fails: an anchor names a seq the chain no longer has |
| rewrite from seq *n* on with a new valid history | **valid** | fails: the hash at the anchored seq differs |

Tests: `TestTamperingIsCaught` in [chainer_test.go](../../internal/auditchain/chainer_test.go). Check by hand with
`qv-relay verify -dsn ... -anchors heads.jsonl` (the file is a dump of the topic, one JSON object per line; use `-source` when
the chain was published under another `-audit-source`).

## Cost

One signed job through the gateway (claim, decide, reserve, HSM sign, store, complete), 300 sequential jobs on SoftHSM and a
local Postgres: **5.8 ms before, 7.6 ms after** (median, +1.8 ms: the two appends `sign.allowed` and `sign.completed`). Measure
again with `QV_MEASURE=1 go test -run TestMeasureCostPerSignedJob ./internal/gateway/`. SoftHSM numbers say nothing about
capacity; the point is the relative cost.

## Gotchas met

- A guard transaction that returns a refusal rolls back, so the refusal record cannot ride in it; it gets its own transaction.
- The test of "guard database down" used to expect a refusal for a malformed request. That is now an outage: no record, no answer.
- Kafka topics are shared between runs, so the end-to-end tests publish under their own `-audit-source`.

## Quiz

1. Why does the chainer select rows that are not chained instead of rows above the last chained seq?
2. What stops one outbox row from being chained twice?
3. Why is `sign.refused` written in a separate transaction and `sign.allowed` not?
4. The signer is up but the gateway's audit table is gone. What happens to a valid job?
5. Someone deletes the last 10 rows of `audit_log` after turning the triggers off. Which check notices?
6. Why does the chain check alone not catch a full rewrite?
7. Kafka is down for an hour. What stops working?

<details>
<summary>Answers</summary>

1. A transaction with a lower seq can commit after a higher one; a watermark would skip it for ever.
2. The advisory lock lets one chainer run; `source_id` is unique; the row is marked `chained_at` in the same transaction.
3. A refusal rolls the guard transaction back. The permission to sign must commit together with the reservation, so there is no signature without a record.
4. The append fails, the guard transaction rolls back, nothing is reserved or signed, and the job is retried.
5. Only the anchors: the remaining chain is valid, but an anchor names a seq it no longer has.
6. A rewritten chain is internally consistent; only the head published earlier disagrees.
7. Nothing in business or signing; the heads are published late, once Kafka is back.

</details>
