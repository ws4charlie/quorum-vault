# Database roles and migrations

Every service connects to Postgres as a role of its own. The certificate's name picks the role (`deploy/postgres/*.pg_ident.conf`), and the DSN user must be that role. Nothing but the owner role `qv` can create, alter or drop anything.

## Business database

| Service | Role | What it may do |
|---|---|---|
| `qv-core` | `qv_core` | The API's writes: customers, deposit addresses, withdrawals, the ledger (journal append-only), refills, `outbox` (insert, and read of `id` only), and the Bitcoin and Solana bookkeeping its endpoints touch (`btc_*`, `sol_*`, `sign_jobs`, with the worker's rights). Reads the worker's other tables and `audit_log` (verify endpoint). |
| `qv-worker` | `qv_worker` | The workflow's writes: scanning, nonces, attempts, utxos, sweeps, cold moves, rebalances, jobs, the ledger, `outbox` insert. Reads customers and deposit addresses without writing them. No `audit_log`. |
| `qv-relay` | `qv_relay` | Read `outbox`, change only its `published_at` and `chained_at`; append to and read `audit_log`; call `outbox_prune()`. Nothing else. |
| `qv-anchor-archiver` | `qv_archiver` | Nothing: it reads Kafka and writes the archive store. |
| `qv-gateway` (link) | `qv_gateway` | Read and update `sign_jobs`. |
| `migrator` (the migration Job on Kubernetes), `admin` (operators, tests, the compose stack) | `qv` | Owner. Two names, one role: the Job holds a certificate that is good for nothing else (no Kafka superuser, no Temporal access), and the operators' `admin` is not kept in a cluster Secret. |

`keysets` (key registry): core and worker select, insert, update; nobody deletes. `drain_moves` and `keyset_drains` (key replacement, migration 0031): the worker selects, inserts and updates them (it plans and drives drains); the core only selects (its admin API shows them). The exact grants are the matrix in `migrations/0030_service_roles.sql`. A table added by a later migration is closed to every service role until that migration grants it.

## Migrations

`qv-core` and `qv-worker` never apply migrations. They check at start that every migration is recorded and that the database has none this binary does not know, and refuse to start otherwise, naming the files. Run the migrations first, as the owner (the `migrator` certificate on Kubernetes, the `admin` certificate by hand):

```bash
DATABASE_URL='postgres://qv@db:5432/quorumvault?sslmode=verify-full&sslrootcert=...&sslcert=admin.crt&sslkey=admin.key' go run ./cmd/qv-migrate
```

Do it before every release, then start the new binaries. `make migrate` does the same for the development database.

## Login

The roles are created `NOLOGIN` and without a password; the certificate is the only credential. A deployment enables login for each role it runs (`ALTER ROLE qv_core LOGIN`). Development, CI and the tests do it with `qv-migrate -enable-login` (`make db-up`).

## Signing zone

The signing zone's Postgres has three roles, `qv_gateway_guard`, `qv_cosigner_b_guard` and `qv_cosigner_c_guard`, made by `qv-migrate -zone signing` (`deploy/postgres/signing_roles.sql`). The gateway and the cosigner apply their schema at start, so each role owns its own guard database and may alter it. That right stops there: `CONNECT` is revoked from `PUBLIC` on every guard database and given to its own role, so none can open another's (cosigner C's certificate cannot open B's guard database, even on a server both use). Make a guard database like this:

```sql
CREATE DATABASE qv_gateway_guard OWNER qv_gateway_guard;
REVOKE CONNECT ON DATABASE qv_gateway_guard FROM PUBLIC;
```

Cosigners B and C have their own certificate names and roles (`cosigner-b` → `qv_cosigner_b_guard`, `cosigner-c` → `qv_cosigner_c_guard`), each the owner of its own guard database. The cosigner's database keeps the name `qv_cosigner_guard` (one per cluster): `CREATE DATABASE qv_cosigner_guard OWNER qv_cosigner_b_guard;` in cluster B, with `qv_cosigner_c_guard` in cluster C.

## Temporal's database

Single-purpose already: the certificate `temporal` maps to the role `temporal`, which owns that database. Unchanged.
