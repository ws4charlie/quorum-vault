# Database roles and migrations

Every service connects to Postgres as a role of its own. The certificate's name picks the role (`deploy/postgres/*.pg_ident.conf`), and the DSN user must be that role. Nothing but the owner role `qv` can create, alter or drop anything.

## Business database

| Service | Role | What it may do |
|---|---|---|
| `qv-core`, `qv-worker` | `qv_core`, `qv_worker` | Read and write the custody tables the code uses (ledger accounts, holds, journal and transactions append-only; withdrawals, sweeps, nonces, deposits, jobs and so on), insert into `outbox`, read `schema_migrations`. No `audit_log`, no delete on the journal. |
| `qv-relay` | `qv_relay` | Read `outbox`, change only its `published_at` and `chained_at`; append to and read `audit_log`; call `outbox_prune()`. Nothing else. |
| `qv-anchor-archiver` | `qv_archiver` | Nothing: it reads Kafka and writes the archive store. |
| `qv-gateway` (link) | `qv_gateway` | Read and update `sign_jobs`. |
| admin, `qv-migrate` | `qv` | Owner. |

The exact grants are the matrix in `migrations/0030_service_roles.sql`. A table added by a later migration is closed to every service role until that migration grants it.

## Migrations

`qv-core` and `qv-worker` never apply migrations. They check at start that every migration is recorded and that the database has none this binary does not know, and refuse to start otherwise, naming the files. Run the migrations first, as the owner (the admin certificate):

```bash
DATABASE_URL='postgres://qv@db:5432/quorumvault?sslmode=verify-full&sslrootcert=...&sslcert=admin.crt&sslkey=admin.key' go run ./cmd/qv-migrate
```

Do it before every release, then start the new binaries. `make migrate` does the same for the development database.

## Login

The roles are created `NOLOGIN` and without a password; the certificate is the only credential. A deployment enables login for each role it runs (`ALTER ROLE qv_core LOGIN`). Development, CI and the tests do it with `qv-migrate -enable-login` (`make db-up`).

## Signing zone

The signing zone's Postgres has two roles, `qv_gateway_guard` and `qv_cosigner_guard`, made by `qv-migrate -zone signing` (`deploy/postgres/signing_roles.sql`). The gateway and the cosigner apply their schema at start, so each role owns its own guard database and may alter it. That right stops there: `CONNECT` is revoked from `PUBLIC` on every guard database and given to its own role, so neither can open the other's. Make a guard database like this:

```sql
CREATE DATABASE qv_gateway_guard OWNER qv_gateway_guard;
REVOKE CONNECT ON DATABASE qv_gateway_guard FROM PUBLIC;
```

Cosigners B and C share one certificate name, so they share one role and are not separated from each other here; distinct names would fix that.

## Temporal's database

Single-purpose already: the certificate `temporal` maps to the role `temporal`, which owns that database. Unchanged.
