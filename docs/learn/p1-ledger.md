# P1 study guide: the Postgres ledger

Code: `internal/ledger/postgres.go`, `invariants.go`. Schema: `migrations/0002_custody_core.sql`.

## 1. Double entry

Every movement writes entries that sum to zero per (chain, asset). A transfer of 30 from A to B is two rows: A -30, B +30. Money never appears or vanishes; it only moves between accounts. A deposit is a transfer from a clearing or suspense account, a withdrawal is a transfer to one.

- Why it helps: any bug that breaks conservation shows up as a non-zero sum, which is cheap to detect (`CheckInvariants`).
- The schema enforces it: a deferred constraint trigger checks every txn's entries at COMMIT. The code is not trusted to be right; the database refuses an unbalanced txn.
- `ledger_entries` is append-only (triggers reject UPDATE/DELETE/TRUNCATE). Corrections are new entries.
- `ledger_accounts.posted` is a cached sum of the account's entries. `CheckInvariants` proves the cache equals the entries.

## 2. Why `held` is not an entry

A hold reserves funds without moving them. A customer asks to withdraw 40: those 40 must stop being spendable now, but the money has not left yet and may never (the withdrawal can fail).

- Entries record facts that happened. A hold is a promise, so it has no entry; it raises `held` and inserts a `ledger_holds` row.
- Available = posted - held. Transfers and new holds check against available.
- `Post` turns the promise into a fact: lowers `held`, writes the two entries, lowers `posted` on the account. Available is unchanged by Post, which is why it cannot fail on funds.
- `Void` drops the promise: lowers `held`, no entries.
- Invariant: `held` equals the sum of pending holds, so it can always be rebuilt.

## 3. Lock ordering

Concurrent transfers must not both spend the same funds, so each locks its accounts (`SELECT ... FOR UPDATE`) and checks available after the lock.

- Deadlock: A->B locks A then B; B->A locks B then A; each holds one and waits for the other. Fix: always lock in sorted ID order, so both lock the lower ID first and one simply waits.
- A hold's Post/Void locks the hold row first, then the accounts. All settle attempts on one hold queue on the hold row, so racing Post and Void have exactly one winner and the loser sees `ErrHoldNotPending`.
- The funds check is in Go after the lock, not the CHECK constraint. The constraint stays as a last line of defence, but it would give an opaque error and abort the transaction.
- Cost: the row lock is held until commit. A hot account therefore serializes at about one commit per transfer (see `docs/measurements/ledger.md`).

## 4. Idempotency

Callers retry (timeouts, workflow replays), so every request carries an ID that becomes `ledger_txns.id`.

- First attempt: `INSERT ... ON CONFLICT DO NOTHING`. One row inserted = we are first.
- Duplicate: nothing inserted, so read the stored `_qv_body_hash` (SHA-256 of the canonical request, amounts as decimal strings so equal numbers match). Same hash: return nil, change nothing. Different hash: `ErrIdempotencyConflict`.
- Concurrent duplicates: the second insert blocks on the unique key until the first transaction ends. If the first committed, the second sees a conflict and takes the replay path; if it rolled back, the second inserts and proceeds. Never a double apply.
- The replay check runs before the funds check, so retrying an already applied transfer succeeds even if the balance has since dropped.
- Post/Void: the ID is the settle txn's. Same ID, same hold, same outcome on a settled hold is nil; anything else on a settled hold is `ErrHoldNotPending`.
- Each operation runs in a savepoint. If it fails after inserting its txn row, the row is rolled back, so a later retry with the same ID is not mistaken for a replay.
- Rolling back the caller's transaction removes everything, and the same ID can then be used again.

## 5. Zero-sum clearing accounts

Clearing accounts model money in flight. A deposit is credited in stages: a source account -> `deposits_pending` when seen, `deposits_pending` -> customer when confirmed. The clearing account is a pipe: it must return to zero once the flow completes.

- Residual != 0 means something is stuck or lost. `ClearingResidual` returns the balance of the named accounts (or every clearing account) so reconciliation jobs can alert on it.
- Dust and unsupported tokens credit `suspense` and stay there until reviewed, so they are visible rather than silently dropped.
- Clearing and source accounts have `allow_negative`, so they can go below zero while a flow is in progress; customer accounts cannot.

## Try it

```bash
export DATABASE_URL='postgres://qv@localhost:55432/quorumvault?sslmode=disable'
QV_REQUIRE_DB=1 go test -race -count=1 -v ./internal/ledger/
```

Experiment: sort the IDs in `lockAccounts` in reverse for one of the two directions and rerun `TestOpposingTransfersNoDeadlock`; the unsorted order is what the test guards against.
