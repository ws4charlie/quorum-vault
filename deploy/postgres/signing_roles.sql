-- Signing-zone Postgres: one role per service that owns a replay-guard database. Run as the owner role (qv) by `qv-migrate -zone signing`.
-- A guard role OWNS its guard database: the gateway and the cosigner apply their schema (store.sql) at start, so they need CREATE and ALTER
-- there. That right stops at the database: CONNECT is revoked from PUBLIC on each guard database and granted to its own role only, so the
-- gateway cannot open a cosigner's guard database and the reverse. Roles have no password and no LOGIN here; the deployment enables login.
--
--   CREATE DATABASE qv_gateway_guard OWNER qv_gateway_guard;
--   REVOKE CONNECT ON DATABASE qv_gateway_guard FROM PUBLIC;
--   CREATE DATABASE qv_cosigner_guard OWNER qv_cosigner_b_guard;   (in cluster B; OWNER qv_cosigner_c_guard in cluster C: one database per cluster, the name kept)
--   REVOKE CONNECT ON DATABASE qv_cosigner_guard FROM PUBLIC;
--
-- Cosigners B and C have their own certificate names (signing/cosigner-b, signing/cosigner-c) and their own roles: B cannot open C's guard database
-- on a server both use, and a certificate of one maps to the other's role nowhere (deploy/postgres/signing.pg_ident.conf).
DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['qv_gateway_guard', 'qv_cosigner_b_guard', 'qv_cosigner_c_guard'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            BEGIN
                EXECUTE format('CREATE ROLE %I NOLOGIN', r);
            EXCEPTION WHEN duplicate_object THEN
                NULL; -- created concurrently
            END;
        END IF;
    END LOOP;
END
$$;
-- The bootstrap database is for the owner only.
DO $$ BEGIN EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC', current_database()); END $$;
