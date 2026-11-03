# T2 — Policy engine, approvals, hash-chained audit log

T2 builds the controls that sit in front of every signature. Before any key is
touched, a request must pass the **policy engine**; if the policy says so, it
must collect votes in the **approval queue**; and every change and decision is
written to an **audit log** that nobody can quietly edit.

## What was built

| Piece | Where | Job |
|---|---|---|
| Policy engine | [internal/policy/policy.go](../../internal/policy/policy.go) | `Evaluate` returns allow / deny / needs_approval with reasons; manages policies and allowlists |
| Approval queue | [internal/approval/approval.go](../../internal/approval/approval.go) | `Vote` enforces dual control and returns a tally |
| Audit log | [internal/audit/audit.go](../../internal/audit/audit.go) | `Append`, `List`, `Verify` over the hash-chained `audit_log` table |

## The policy rules, in order

[`Evaluate`](../../internal/policy/policy.go#L94) runs these checks:

| # | Rule | Kind | Reason string |
|---|---|---|---|
| 0 | Wallet has no policy row | hard | `no policy` |
| 1 | Destination not in the wallet's allowlist (case-insensitive) | hard | `destination not allowlisted` |
| 2 | `value > per_tx_limit` | hard | `exceeds per-tx limit` |
| 3 | Non-denied requests in the velocity window `>= velocity_max_tx` | hard | `velocity limit reached` |
| 4a | Wallet tier is `cold` | soft | `cold wallet requires approval` |
| 4b | `value > approval_threshold` | soft | `exceeds approval threshold` |
| 4c | `spent_24h + value > daily_limit` | soft | `exceeds daily limit` |

- All hard rules run, so a deny lists **every** reason that failed. The caller
  can show "not allowlisted AND over the per-tx limit" in one go.
- Soft rules run only when no hard rule failed ([policy.go:140](../../internal/policy/policy.go#L140)).
- `spent_24h` sums requests with status `approved`, `signed` or
  `pending_approval`. Pending counts because it may still be approved: if it
  did not, ten pending requests could each slip under the daily limit.
- Velocity counts every status except `denied`. A denied request never got near
  a key, so it should not use up the rate budget.
- The request under evaluation is excluded by id, so `Evaluate` gives the same
  answer whether the caller inserted the row before or after asking.
- Money is `*big.Int` everywhere. Postgres `numeric(78,0)` is read as text
  (`value_wei::text`) and parsed with `SetString`. Never a float.
- Time comes from an injected `now func() time.Time`, and window starts are sent
  to the DB as parameters, so tests can pin the clock to the second.

### Why hard-deny before approval

A hard rule is something **no human may override**: a destination the
organisation never vetted, an amount over the absolute cap, a burst of requests
that looks like a compromised client. If approvals could rescue those, the
controls would only be as strong as the most careless approver, and a phished
approver could move funds anywhere. So deny wins: a cold-wallet request to an
unknown address is denied, not queued for approval
(test `hard_deny_wins_over_soft_rules`).

Soft rules mark requests that are allowed **in principle** but large or
sensitive enough that a second person must look.

## Dual control

[`Vote`](../../internal/approval/approval.go#L46) enforces:

1. Request must be `pending_approval` (`ErrNotPending`).
2. Approver != requester (`ErrSelfApproval`). One person can never move funds alone.
3. One vote per approver per request (`ErrDuplicateVote`). This uses the DB
   unique constraint `(request_id, approver)` and maps Postgres error `23505`
   ([approval.go:64](../../internal/approval/approval.go#L64)). A Go-side "have
   they voted?" check would race; the constraint cannot.
4. The tally is read back from the DB after the insert, so two approvers voting
   at the same moment both count.
5. Any reject ends the request (`Rejected`, `Done`). Reaching
   `required_approvals` distinct approvals ends it as approved.

`Vote` never touches `sign_requests.status`; the signing orchestrator (T4)
reads the `Tally` and moves the status.

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
  no transaction, so a policy update commits and then the audit append runs.
  If the append fails, the change is in place and the caller gets an error.

## Quiz

1. A cold-wallet request for 1 wei to an allowlisted address: what is the outcome and why?
2. A hot-wallet request to an unknown address, over the per-tx limit: what reasons come back?
3. Why does `spent_24h` include `pending_approval` requests?
4. Why are `denied` requests left out of the velocity count?
5. A request was created exactly 24h + 1s ago. Does it count toward `spent_24h`?
6. Why is duplicate-vote detection done by a unique constraint and not a SELECT first?
7. What stops the requester from approving their own request?
8. Someone with superuser access disables the trigger and changes the payload of seq 3. What does `Verify` report?
9. The same person rewrites seq 3 and recomputes every hash from 3 to the end. Does `Verify` catch it? What would?
10. Why does `Append` take a Postgres advisory lock?
11. Why does `Append` pass the payload through `::jsonb::text` before hashing?
12. Why are wei values never converted to float64?

<details>
<summary>Answers</summary>

1. `needs_approval` with `cold wallet requires approval`. Cold wallets always need approval, whatever the amount.
2. `deny` with `destination not allowlisted`, `exceeds per-tx limit` (plus `velocity limit reached` if that also fails). Hard reasons accumulate.
3. A pending request may still be approved. Leaving it out would let many pending requests each pass the daily limit.
4. A denied request never reached a key, so it did not use up any of the rate budget.
5. No. The window is `created_at > now - 24h`.
6. Two concurrent votes from the same approver could both pass a SELECT check. The unique constraint makes the DB reject the second insert atomically.
7. `Vote` returns `ErrSelfApproval` when `approver == req.Requester`.
8. `ok = false`, `firstBadSeq = 3`: the recomputed hash of row 3 no longer matches its stored hash.
9. No: the chain is internally consistent again. Anchoring the head hash outside the attacker's reach (another system, WORM storage, an HSM signature) would.
10. To serialize appends: each must read the current tail hash and write the next row without another append slipping in between.
11. jsonb reorders keys and changes spacing. Hashing the normalized form makes `Verify`'s recomputation, which reads jsonb back, match.
12. float64 holds only 53 bits of integer precision; 1 ETH is already 10^18 wei, so amounts would be silently rounded.
</details>
