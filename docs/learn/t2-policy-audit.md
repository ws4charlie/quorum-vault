# T2 — Hash-chained audit log

The audit log is a table nobody can quietly edit. (This page once also covered
the policy engine and approval queue of the /v1 demo; those were removed.)

## What was built

| Piece | Where | Job |
|---|---|---|
| Audit log | [internal/audit/audit.go](../../internal/audit/audit.go) | `Append`, `List`, `Verify` over the hash-chained `audit_log` table |

## Hash chain vs append-only trigger

Each row stores `prev_hash` and
`hash = SHA-256(prev_hash || canonical JSON{seq, at, actor, type, request_id, wallet_id, key_id, payload})`.
Genesis `prev_hash` is 32 zero bytes. See [`computeHash`](../../internal/audit/audit.go#L67).

| Defence | Stops | Does not stop |
|---|---|---|
| DB trigger rejecting UPDATE/DELETE/TRUNCATE | App bugs and ordinary SQL users changing history | Anyone who can `ALTER TABLE ... DISABLE TRIGGER`, a superuser, or someone editing the data files |
| Hash chain + `Verify` | Undetected edits or deletions in the middle: the changed row's hash, or the next row's `prev_hash`, no longer matches | Rewriting the **whole** chain from the edit point onward (it is all public data, no secret), or cutting rows off the end |

Neither one alone, nor both together, stops a powerful insider who rewrites
the chain. The usual fix is to **anchor** the chain head somewhere the attacker
does not control: publish the latest hash periodically to another system, a
WORM bucket, or a blockchain, or sign it with an HSM key. Then a rewrite no
longer matches the anchored value. That is out of scope here.

### Gotchas met

- **jsonb rewrites JSON.** Postgres stores `{"b":1,"a":2}` as `{"a": 2, "b": 1}`.
  If we hashed the caller's bytes, `Verify` (which reads jsonb back) would fail.
  `Append` first normalizes the payload with `SELECT $1::jsonb::text` and hashes
  that form.
- **Timestamps.** Postgres keeps microseconds; Go has nanoseconds. `At` is
  truncated to microseconds before hashing so it round-trips exactly.
- **UUID case.** Postgres returns UUIDs lowercase; `Append` normalizes them first.
- **Gap-free seq.** Under the advisory lock ([audit.go:146](../../internal/audit/audit.go#L146)),
  `Append` reads the tail row and writes `seq = last + 1` explicitly instead of
  using the sequence, which can leave gaps when a transaction rolls back.
- **Audit is not in the same transaction as the change.** `domain.Auditor` takes
  no transaction, so a change commits and then the audit append runs.
  If the append fails, the change is in place and the caller gets an error.

## Quiz

1. Someone with superuser access disables the trigger and changes the payload of seq 3. What does `Verify` report?
2. The same person rewrites seq 3 and recomputes every hash from 3 to the end. Does `Verify` catch it? What would?
3. Why does `Append` take a Postgres advisory lock?
4. Why does `Append` pass the payload through `::jsonb::text` before hashing?

<details>
<summary>Answers</summary>

1. `ok = false`, `firstBadSeq = 3`: the recomputed hash of row 3 no longer matches its stored hash.
2. No: the chain is internally consistent again. Anchoring the head hash outside the attacker's reach (another system, WORM storage, an HSM signature) would.
3. To serialize appends: each must read the current tail hash and write the next row without another append slipping in between.
4. jsonb reorders keys and changes spacing. Hashing the normalized form makes `Verify`'s recomputation, which reads jsonb back, match.
</details>
