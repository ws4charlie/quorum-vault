-- One least-privilege database role per service. Until now core, worker, relay and archiver all connected as the owner role qv (the only
-- restricted one was qv_gateway, 0004), so a compromised relay could have rewritten the ledger. Each service now has a role with exactly the rights
-- its code uses; the owner qv stays for migrations (cmd/qv-migrate) and operator tools (the "admin" certificate).
--
-- The Postgres map (deploy/postgres/business.pg_ident.conf) sends each certificate name to its own role:
--   core -> qv_core   worker -> qv_worker   relay -> qv_relay   archiver -> qv_archiver   gateway-link -> qv_gateway   admin -> qv
-- A login role must equal the DSN user, so every service's DSN names its own role.
--
-- Roles are NOLOGIN here, as 0004 does for qv_gateway: no password, and the deployment enables login (cmd/qv-migrate -enable-login in
-- development, CI and tests). None of them may CREATE, ALTER or DROP anything: qv-core and qv-worker only CHECK the migrations (db.Check).
-- Roles are cluster-global, so creation is guarded; grants are per database, so they live here.

DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['qv_core', 'qv_worker', 'qv_relay', 'qv_archiver'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            BEGIN
                EXECUTE format('CREATE ROLE %I NOLOGIN', r);
            EXCEPTION WHEN duplicate_object THEN
                NULL; -- created concurrently by another database's migration
            END;
        END IF;
    END LOOP;
END
$$;

-- Nothing is open by default. Existing objects: PUBLIC gets no rights (it keeps USAGE on the schema for names, but not CREATE).
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
-- No temporary tables either: TEMPORARY is a database privilege PUBLIC has by default, and no service needs it.
DO $$ BEGIN EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database()); END $$;
-- New objects made by whoever runs the migrations (the owner): no rights for PUBLIC or any service role until a migration grants them.
-- (PG's default would give PUBLIC EXECUTE on every new function.) A later migration that adds a table GRANTs what its services need in that same migration; nothing
-- is open until then.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['qv_core', 'qv_worker', 'qv_relay', 'qv_archiver', 'qv_gateway'] LOOP
        EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', r);
        EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %I', r);
        EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM %I', r);
        EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', r);
        EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM %I', r);
        EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM %I', r);
    END LOOP;
END
$$;
-- qv_gateway keeps what 0004 gave it (re-granted: the loop above reset every service role to a clean state).
GRANT SELECT, UPDATE ON sign_jobs TO qv_gateway;

-- The matrix: (role, table, privileges). Derived from the queries each service runs, and confirmed by running the end-to-end suites under
-- these roles (docs/runbooks/database-roles.md has the same table in prose). A GRANT of INSERT also grants USAGE on the sequences the table
-- owns (serial and identity columns), so a service that may insert can number its rows.
CREATE FUNCTION pg_temp.grant_matrix(m text[][]) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    i int;
    seq record;
BEGIN
    FOR i IN 1 .. array_length(m, 1) LOOP
        EXECUTE format('GRANT %s ON %I TO %I', m[i][3], m[i][2], m[i][1]);
        IF m[i][3] ~* 'insert' THEN
            FOR seq IN
                SELECT s.oid::regclass AS name FROM pg_class s
                JOIN pg_depend d ON d.objid = s.oid AND d.deptype IN ('a', 'i')
                WHERE s.relkind = 'S' AND d.refobjid = format('public.%I', m[i][2])::regclass
            LOOP
                EXECUTE format('GRANT USAGE ON SEQUENCE %s TO %I', seq.name, m[i][1]);
            END LOOP;
        END IF;
    END LOOP;
END
$$;

SELECT pg_temp.grant_matrix(ARRAY[
    -- ---- qv_core and qv_worker: the business application. Both build the same custody.Service, but they do different work:
    -- qv-core serves the API (customers, deposit addresses, withdrawal requests and approvals, refill ceremonies, cancels) and writes only what
    -- those do; qv-worker runs the workflow activities (scanning, nonces, attempts, signing jobs, sweeps, cold moves, rebalances) and reads
    -- customers and deposit addresses without writing them. Core reads the worker's tables (reconciliation and balances). Neither may touch
    -- audit_log's contents (only the relay writes it; core reads it for the verify endpoint), and the ledger journal is append-only.
    ['qv_core',   'assets',                   'SELECT, INSERT, UPDATE'],
    ['qv_worker', 'assets',                   'SELECT, INSERT, UPDATE'],
    ['qv_core',   'audit_log',                'SELECT'],
    ['qv_core',   'btc_attempts',             'SELECT'],
    ['qv_worker', 'btc_attempts',             'SELECT, INSERT, UPDATE, DELETE'],
    ['qv_core',   'btc_batch_items',          'SELECT, UPDATE, DELETE'],
    ['qv_worker', 'btc_batch_items',          'SELECT, INSERT, UPDATE, DELETE'],
    ['qv_core',   'btc_batches',              'SELECT, UPDATE'],
    ['qv_worker', 'btc_batches',              'SELECT, INSERT, UPDATE'],
    ['qv_core',   'btc_fee_cap_changes',      'SELECT'],
    ['qv_worker', 'btc_fee_cap_changes',      'SELECT'],
    ['qv_core',   'btc_refusals',             'SELECT'],
    ['qv_worker', 'btc_refusals',             'SELECT, INSERT, UPDATE, DELETE'],
    ['qv_core',   'btc_utxos',                'SELECT'],
    ['qv_worker', 'btc_utxos',                'SELECT, INSERT, UPDATE'],
    ['qv_core',   'chain_cursors',            'SELECT'],
    ['qv_worker', 'chain_cursors',            'SELECT, INSERT, UPDATE'],
    ['qv_core',   'cold_moves',               'SELECT'],
    ['qv_worker', 'cold_moves',               'SELECT, INSERT, UPDATE'],
    ['qv_core',   'consolidations',           'SELECT'],
    ['qv_worker', 'consolidations',           'SELECT, INSERT, UPDATE'],
    ['qv_core',   'customers',                'SELECT, INSERT'],
    ['qv_worker', 'customers',                'SELECT'],
    ['qv_core',   'deferred_deposits',        'SELECT'],
    ['qv_worker', 'deferred_deposits',        'SELECT, INSERT, DELETE'],
    ['qv_core',   'deposit_addresses',        'SELECT, INSERT'],
    ['qv_worker', 'deposit_addresses',        'SELECT'],
    ['qv_core',   'deposits',                 'SELECT'],
    ['qv_worker', 'deposits',                 'SELECT, INSERT'],
    ['qv_core',   'evm_nonce_allocations',    'SELECT'],
    ['qv_worker', 'evm_nonce_allocations',    'SELECT, INSERT, UPDATE'],
    ['qv_core',   'evm_nonces',               'SELECT'],
    ['qv_worker', 'evm_nonces',               'SELECT, INSERT, UPDATE'],
    ['qv_core',   'evm_tx_attempts',          'SELECT'],
    ['qv_worker', 'evm_tx_attempts',          'SELECT, INSERT'],
    ['qv_core',   'factory_state',            'SELECT'],
    ['qv_worker', 'factory_state',            'SELECT, INSERT, UPDATE'],
    ['qv_core',   'hot_low_alerts',           'SELECT'],
    ['qv_worker', 'hot_low_alerts',           'SELECT, INSERT, DELETE'],
    ['qv_core',   'ledger_accounts',          'SELECT, INSERT, UPDATE'],
    ['qv_worker', 'ledger_accounts',          'SELECT, INSERT, UPDATE'],
    ['qv_core',   'ledger_entries',           'SELECT, INSERT'],
    ['qv_worker', 'ledger_entries',           'SELECT, INSERT'],
    ['qv_core',   'ledger_holds',             'SELECT, INSERT, UPDATE'],
    ['qv_worker', 'ledger_holds',             'SELECT, INSERT, UPDATE'],
    ['qv_core',   'ledger_txns',              'SELECT, INSERT'],
    ['qv_worker', 'ledger_txns',              'SELECT, INSERT'],
    ['qv_core',   'outbox',                   'INSERT'],
    ['qv_worker', 'outbox',                   'INSERT'],
    ['qv_core',   'partitions',               'SELECT, INSERT, UPDATE'],
    ['qv_worker', 'partitions',               'SELECT, INSERT, UPDATE'],
    ['qv_core',   'rebalance_gas_alerts',     'SELECT'],
    ['qv_worker', 'rebalance_gas_alerts',     'SELECT, INSERT, DELETE'],
    ['qv_core',   'rebalance_moves',          'SELECT'],
    ['qv_worker', 'rebalance_moves',          'SELECT, INSERT, UPDATE'],
    ['qv_core',   'refills',                  'SELECT, INSERT, UPDATE'],
    ['qv_worker', 'refills',                  'SELECT, INSERT, UPDATE'],
    ['qv_core',   'scan_halts',               'SELECT'],
    ['qv_worker', 'scan_halts',               'SELECT, INSERT'],
    ['qv_core',   'scanned_blocks',           'SELECT'],
    ['qv_worker', 'scanned_blocks',           'SELECT, INSERT, UPDATE'],
    ['qv_core',   'schema_migrations',        'SELECT'],
    ['qv_worker', 'schema_migrations',        'SELECT'],
    ['qv_core',   'sign_jobs',                'SELECT, DELETE'],
    ['qv_worker', 'sign_jobs',                'SELECT, INSERT, UPDATE, DELETE'],
    ['qv_core',   'sol_cold_nonce_retired',   'SELECT, INSERT, UPDATE'],
    ['qv_worker', 'sol_cold_nonce_retired',   'SELECT, INSERT, UPDATE'],
    ['qv_core',   'sol_cold_ops',             'SELECT, INSERT, UPDATE'],
    ['qv_worker', 'sol_cold_ops',             'SELECT, INSERT, UPDATE'],
    ['qv_core',   'sol_nonce_accounts',       'SELECT, UPDATE'],
    ['qv_worker', 'sol_nonce_accounts',       'SELECT, INSERT, UPDATE'],
    ['qv_core',   'sol_nonce_allocations',    'SELECT'],
    ['qv_worker', 'sol_nonce_allocations',    'SELECT, INSERT, UPDATE'],
    ['qv_core',   'sol_tx_attempts',          'SELECT'],
    ['qv_worker', 'sol_tx_attempts',          'SELECT, INSERT'],
    ['qv_core',   'sweep_items',              'SELECT'],
    ['qv_worker', 'sweep_items',              'SELECT, INSERT'],
    ['qv_core',   'sweep_moves',              'SELECT'],
    ['qv_worker', 'sweep_moves',              'SELECT, INSERT'],
    ['qv_core',   'sweeps',                   'SELECT'],
    ['qv_worker', 'sweeps',                   'SELECT, INSERT, UPDATE'],
    ['qv_core',   'withdrawals',              'SELECT, INSERT, UPDATE'],
    ['qv_worker', 'withdrawals',              'SELECT, UPDATE'],
    -- ---- qv_relay: publishes the outbox, chains audit events, prunes. It changes only the two timestamps of an outbox row (the trigger
    -- enforces the rest), appends to audit_log (the trigger makes it append-only) and reads it back for the head anchors and verification.
    -- It has no right on any ledger, withdrawal, nonce or job table.
    ['qv_relay',  'outbox',                 'SELECT'],
    ['qv_relay',  'audit_log',              'SELECT, INSERT'],
    ['qv_relay',  'schema_migrations',      'SELECT']
]::text[][]);
-- Column-level. Core and worker enqueue with INSERT ... ON CONFLICT (id) DO NOTHING, which must read the conflicting id and nothing else of the row.
GRANT SELECT (id) ON outbox TO qv_core, qv_worker;
-- The relay may change only published_at and chained_at of an outbox row.
GRANT UPDATE (published_at, chained_at) ON outbox TO qv_relay;
-- outbox_prune() is SECURITY DEFINER (owned by the owner role): the relay may call it, no other service may.
REVOKE ALL ON FUNCTION outbox_prune(interval, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION outbox_prune(interval, int) TO qv_relay;

-- qv_archiver reads Kafka and writes an archive store, never this database: its certificate maps to a role with no rights at all, so the
-- certificate opens nothing here.

-- ---- Tables other changes add in the same batch (grants go in the migration that adds the table, or here when that PR merged first):
--   keysets (0029, K1): qv_core and qv_worker SELECT, INSERT, UPDATE; no DELETE; no other role.   << PLACE FOR THE keysets GRANT >>
