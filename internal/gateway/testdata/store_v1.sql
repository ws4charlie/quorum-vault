-- Replay guard: the signing zone's own record of what it signed. Applied by the
-- gateway at start, in a database the business zone cannot reach. Idempotent.

-- One row per intent ID, written when its first signature is released.
CREATE TABLE IF NOT EXISTS signed_intents (
    intent_id   text PRIMARY KEY,
    intent_hash bytea NOT NULL,
    kind        text NOT NULL,
    chain       text NOT NULL,
    asset       text NOT NULL,
    amount      numeric(78,0) NOT NULL,
    sender      text NOT NULL,
    nonce       numeric(20,0) NOT NULL,
    created_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS signed_intents_window ON signed_intents (chain, kind, created_at);

-- One row per transaction digest. Reserved first (signature NULL), finished after signing.
-- A replacement at the same nonce adds a row.
CREATE TABLE IF NOT EXISTS signed_digests (
    digest      bytea PRIMARY KEY,
    intent_id   text NOT NULL REFERENCES signed_intents (intent_id),
    nonce       numeric(20,0) NOT NULL,
    tip         numeric(78,0) NOT NULL,
    fee_cap     numeric(78,0) NOT NULL,
    signature   bytea,                    -- NULL while reserved: caps and nonce are taken, signer not done
    reserved_at timestamptz NOT NULL,
    signed_at   timestamptz
);
ALTER TABLE signed_digests ALTER COLUMN signature DROP NOT NULL;

-- Which intent owns a (chain, sender, nonce). A cancel consumes the nonce.
CREATE TABLE IF NOT EXISTS nonce_claims (
    chain     text NOT NULL,
    sender    text NOT NULL,
    nonce     numeric(20,0) NOT NULL,
    intent_id text NOT NULL REFERENCES signed_intents (intent_id),
    kind      text NOT NULL,
    PRIMARY KEY (chain, sender, nonce)
);

-- The zone's own hash-chained audit log (same shape as the business database's, see internal/audit): every decision, signed or
-- refused, in this database, so it does not depend on the business zone being up or honest. Append-only by trigger.
CREATE TABLE IF NOT EXISTS audit_log (
    seq        bigserial PRIMARY KEY,
    at         timestamptz NOT NULL,
    actor      text NOT NULL,
    type       text NOT NULL,
    request_id uuid,
    wallet_id  uuid,
    key_id     uuid,
    payload    jsonb,
    prev_hash  bytea NOT NULL,
    hash       bytea NOT NULL,
    source_id  uuid UNIQUE
);

CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;

CREATE OR REPLACE TRIGGER audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE OR REPLACE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();
