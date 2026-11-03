# T0 — Foundations: PKCS#11 sessions, the schema, pinned deps

T0 builds nothing a user sees. It lays the ground the other tasks stand on:
a PKCS#11 session layer, the full Postgres schema, the shared Go types, and every
third-party dependency resolved up front.

## What was built

| Piece | Where | Why |
|---|---|---|
| PKCS#11 session layer | [internal/hsm/session.go](../../internal/hsm/session.go) | Open a token by label, log in once, hand out sessions safely to many goroutines |
| Test helpers | [internal/hsm/hsmtest](../../internal/hsm/hsmtest/hsmtest.go), [internal/db/dbtest](../../internal/db/dbtest/dbtest.go) | Each test gets a real token and its own throw-away database |
| Schema | [migrations/0001_init.sql](../../migrations/0001_init.sql) | All tables, constraints and the append-only audit triggers |
| Migration runner | [internal/db/db.go](../../internal/db/db.go) | Embedded SQL, applied once each, tracked in `schema_migrations` |
| Shared types | [internal/domain](../../internal/domain/domain.go), [internal/signer](../../internal/signer/signer.go) | The contract T1–T4 code against |
| Token setup | [scripts/setup-softhsm.sh](../../scripts/setup-softhsm.sh) | Repo-local SoftHSM tokens, idempotent |
| Dependency pins | [internal/deps/deps.go](../../internal/deps/deps.go), `go.mod` | Resolve version clashes once, before parallel work |

## PKCS#11 in five nouns

PKCS#11 (also called Cryptoki) is a C API that every HSM vendor implements.
Your program never sees a private key; it asks the token to use one.

1. **Library** — a shared object (`libsofthsm2.so`) that implements the API.
   You load it and call `C_Initialize` once per process
   ([session.go:119](../../internal/hsm/session.go#L119)).
2. **Slot** — a reader position. A slot may hold a **token**.
3. **Token** — the actual key store (a smart card, an HSM partition, or a
   SoftHSM directory). It has a label, a Security Officer (SO) PIN and a user PIN.
4. **Session** — a handle you open on a token to do work. Sessions are cheap,
   but one session runs one operation at a time.
5. **Object** — keys, certificates, data. Each has attributes such as
   `CKA_LABEL`, `CKA_ID`, `CKA_SENSITIVE` (value never leaves in clear) and
   `CKA_EXTRACTABLE` (can it be wrapped out at all).

**Login is per slot, for the whole application.** Logging in on one session
logs every session of the process in on that slot. It stays logged in until the
last session on the slot closes. Two consequences in our code:

- A second `C_Login` returns `CKR_USER_ALREADY_LOGGED_IN`; we treat it as success
  ([session.go:160](../../internal/hsm/session.go#L160)).
- The `Token` keeps its first session open until `Close`, so the login never
  silently lapses.

### Session pool

`Token.WithSession` ([session.go:203](../../internal/hsm/session.go#L203))
borrows a session from a buffered channel of up to 4, creating them lazily. After
`fn` returns, the session goes back to the pool, unless the error says the
session is gone (`CKR_SESSION_HANDLE_INVALID` etc.), then it is closed
([session.go:209](../../internal/hsm/session.go#L209)). Rule for callers: finish
any operation you start (`C_SignInit` must be followed by `C_Sign`), because the
next borrower gets the same session.

### One `Lib` per path

`C_Initialize` twice in one process fails with `CKR_CRYPTOKI_ALREADY_INITIALIZED`,
and `C_Finalize` kills every session in the process. So `LoadLib` keeps a global
map path -> `*Lib` with a reference count; the last `Close` finalizes
([session.go:100](../../internal/hsm/session.go#L100),
[session.go:129](../../internal/hsm/session.go#L129)).

## Why find tokens by label

SoftHSM assigns a new random slot ID every time a token is initialised (you can
see IDs like `Slot 376419291` in `softhsm2-util --show-slots`). Real HSMs reorder
slots when partitions are added. A hard-coded slot number would point at the
wrong token, or none. So `findSlot` walks `C_GetSlotList(true)` and compares each
token's label ([session.go:169](../../internal/hsm/session.go#L169)). PKCS#11
labels are fixed 32-byte, space-padded fields, hence the `TrimRight`
([session.go:179](../../internal/hsm/session.go#L179)).

### Repo-local token store

`scripts/setup-softhsm.sh` writes `./data/softhsm/softhsm2.conf` pointing at
`./data/softhsm/tokens`. `LoadLib` sets `SOFTHSM2_CONF` to it if unset
([session.go:76](../../internal/hsm/session.go#L76)). Each git worktree therefore
has its own tokens, and parallel hands never see each other's keys.

## The append-only audit log

Two triggers call one function that always raises
([0001_init.sql:109](../../migrations/0001_init.sql#L109)):

- a `BEFORE UPDATE OR DELETE ... FOR EACH ROW` trigger
  ([0001_init.sql:113](../../migrations/0001_init.sql#L113));
- a `BEFORE TRUNCATE ... FOR EACH STATEMENT` trigger
  ([0001_init.sql:117](../../migrations/0001_init.sql#L117)). Row triggers do not
  fire on `TRUNCATE`, so it needs its own.

What this protects against: application bugs and casual edits, even by the table
owner. What it does **not** stop: a superuser who drops the trigger. That is why
T2 also hash-chains rows: an edit made after disabling the trigger breaks the
chain, and `Verify` finds the first bad `seq`. The table has no foreign keys so
audit rows outlive the wallets and keys they describe.

Another invariant lives in the schema too: the partial unique index
`keys_one_active_per_wallet` ([0001_init.sql:32](../../migrations/0001_init.sql#L32))
makes "two active keys for one wallet" impossible, whatever the Go code does.

## Why all deps are pinned in T0

T1 (HSM), T2 (policy) and T3 (MPC) run in parallel. If each added its own
modules, all three would edit `go.mod`/`go.sum` and merge conflicts would follow.
Worse, tss-lib and go-ethereum both pull secp256k1/btcec/crypto modules, and a
clash found late blocks a task. So T0 imports everything once in
[internal/deps/deps.go](../../internal/deps/deps.go) (blank imports keep
`go mod tidy` from dropping them) and proves `go build ./...` works.

Gotchas hit:

- **`replace` directives do not propagate.** tss-lib's own `go.mod` replaces
  `github.com/agl/ed25519` with `github.com/binance-chain/edwards25519`; consumers
  must copy that line or the build fails with "module ... does not contain
  package github.com/agl/ed25519". See the `replace` in `go.mod`.
- **tss-lib `/v4` has no tag yet**: it resolves only as a pseudo-version of
  `master` (`v4.0.0-20260923032227-f204718ae595`). `/v3 v3.0.0` is the newest tag.
- **Minimum Go is 1.25**, forced by go-ethereum v1.17.10 and pgx v5.12.0.

## Signatures: low-S

For any ECDSA signature `(r, s)`, `(r, N-s)` is also valid. Ethereum (EIP-2)
accepts only `s <= N/2` to stop transaction-hash malleability.
`signer.NormalizeLowS` ([signer.go:41](../../internal/signer/signer.go#L41)) flips
high values; every backend must call it before returning.

## Quiz

1. Why can't the code store "slot 0" in config for the `quorumvault` token?
2. You log in on session A. Is session B on the same slot logged in?
3. What does `CKR_USER_ALREADY_LOGGED_IN` mean in a multi-token process, and why is it safe to ignore here?
4. What happens to the other goroutines' sessions if one part of the program calls `C_Finalize`?
5. Why does the audit log need a separate TRUNCATE trigger?
6. Name one attack the append-only trigger does not stop, and what catches it.
7. Why is `audit_log` free of foreign keys?
8. What enforces "at most one active key per wallet" even if Go code has a bug?
9. Why does `deps.go` exist, and what breaks if it is deleted and `go mod tidy` runs?
10. Why did the build fail on `github.com/agl/ed25519`, and how was it fixed?
11. Why must a session borrower finish any `C_SignInit` it starts?
12. Why are `*big.Int` fields marshalled to JSON as strings?

<details>
<summary>Answers</summary>

1. Slot IDs are not stable: SoftHSM assigns a new random ID per init, and HSMs reorder slots. Find by label instead.
2. Yes. Login state is per slot for the whole application.
3. Another `Token` (or another open) already logged the app in on that slot; the desired state (logged in as user) already holds.
4. They all die: `C_Finalize` ends every session in the process. Hence one ref-counted `Lib` per path.
5. Row-level triggers do not fire on `TRUNCATE`; only a statement-level `BEFORE TRUNCATE` trigger does.
6. A superuser can drop or disable the trigger and edit rows. The hash chain (`prev_hash`/`hash`) makes the edit detectable by `Verify`.
7. Audit rows must outlive the rows they describe; an FK would block deletes or cascade into the log.
8. The partial unique index `keys_one_active_per_wallet` on `keys(wallet_id) WHERE state='active'`.
9. It keeps not-yet-used modules in `go.mod` so parallel tasks never edit `go.mod`/`go.sum`. Without it, tidy drops them and the next task that imports one must change `go.mod`.
10. tss-lib depends on `agl/ed25519` but its own `go.mod` `replace`s it; replaces apply only in the main module, so we copied the `replace` into ours.
11. The session returns to the pool; the next borrower would hit `CKR_OPERATION_ACTIVE`.
12. Wei values exceed 2^53, the exact-integer limit of JSON numbers in JavaScript/float64.

</details>
