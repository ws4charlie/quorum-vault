-- Database role for the signing gateway: it may read and update sign_jobs and
-- nothing else in the business database. Roles are cluster-global, so creation
-- is guarded and the file is safe to run on a server that already has the role.
-- The role has no password and no LOGIN here; operators grant both out of band.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qv_gateway') THEN
        BEGIN
            CREATE ROLE qv_gateway NOLOGIN;
        EXCEPTION WHEN duplicate_object THEN
            NULL; -- created concurrently by another database's migration
        END;
    END IF;
END
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM qv_gateway;
GRANT USAGE ON SCHEMA public TO qv_gateway;
GRANT SELECT, UPDATE ON sign_jobs TO qv_gateway;
