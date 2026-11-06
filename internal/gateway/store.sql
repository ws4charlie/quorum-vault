-- Replay guard: the signing zone's own record of what it signed. Applied by the
-- gateway at start, in a database the business zone cannot reach. Idempotent.

-- One row per intent ID, written when its first signature is released. "claims" lists what the transaction consumes
-- (the codec decides: EVM one claim, sender plus nonce); sender is the account it belongs to. nonce is the EVM-only
-- column of the first schema: it stays for the rows already written and is no longer written.
CREATE TABLE IF NOT EXISTS signed_intents (
    intent_id   text PRIMARY KEY,
    intent_hash bytea NOT NULL,
    kind        text NOT NULL,
    chain       text NOT NULL,
    asset       text NOT NULL,
    amount      numeric(78,0) NOT NULL,
    sender      text NOT NULL,
    nonce       numeric(20,0),
    created_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS signed_intents_window ON signed_intents (chain, kind, created_at);
ALTER TABLE signed_intents ALTER COLUMN nonce DROP NOT NULL;
ALTER TABLE signed_intents ADD COLUMN IF NOT EXISTS claims text[];

-- One row per transaction digest. Reserved first (signature NULL), finished after signing. A transaction with several
-- signatures has one row per digest, all with the same payload_hash; a replacement adds rows with another payload_hash
-- and higher fees. "fees" are the fee components the codec compares (EVM: fee cap, tip); tip, fee_cap and nonce are the
-- EVM-only columns of the first schema, kept for rows already written.
CREATE TABLE IF NOT EXISTS signed_digests (
    digest      bytea PRIMARY KEY,
    intent_id   text NOT NULL REFERENCES signed_intents (intent_id),
    nonce       numeric(20,0),
    tip         numeric(78,0),
    fee_cap     numeric(78,0),
    signature   bytea,                    -- NULL while reserved: caps and claims are taken, signer not done
    reserved_at timestamptz NOT NULL,
    signed_at   timestamptz
);
ALTER TABLE signed_digests ALTER COLUMN signature DROP NOT NULL;
ALTER TABLE signed_digests ALTER COLUMN nonce DROP NOT NULL;
ALTER TABLE signed_digests ALTER COLUMN tip DROP NOT NULL;
ALTER TABLE signed_digests ALTER COLUMN fee_cap DROP NOT NULL;
ALTER TABLE signed_digests ADD COLUMN IF NOT EXISTS fees numeric(78,0)[];
ALTER TABLE signed_digests ADD COLUMN IF NOT EXISTS payload_hash bytea;

-- Which intent owns a claim on a chain. A cancel takes over the claims of what it frees.
CREATE TABLE IF NOT EXISTS exclusive_claims (
    chain     text NOT NULL,
    claim     text NOT NULL,
    intent_id text NOT NULL REFERENCES signed_intents (intent_id),
    kind      text NOT NULL,
    PRIMARY KEY (chain, claim)
);

-- A claim carries a pin: an opaque string the codec sets (Bitcoin: the value of the input the claim names; EVM: none, the empty
-- string). A different pin on a claim that exists is refused. tx_identity is the codec's identity of the transaction a digest
-- belongs to (Bitcoin: the txid, which does not commit to input values); one identity has one payload hash.
ALTER TABLE exclusive_claims ADD COLUMN IF NOT EXISTS pin text NOT NULL DEFAULT '';
ALTER TABLE signed_digests ADD COLUMN IF NOT EXISTS tx_identity text;
CREATE INDEX IF NOT EXISTS signed_digests_identity ON signed_digests (tx_identity) WHERE tx_identity IS NOT NULL;

-- Upgrade of a guard database written by the nonce-only schema. Idempotent, and a no-op on a fresh database.
-- An EVM claim is "<sender>#<nonce>", the sender in the form the codec reports (checksum case).
UPDATE signed_intents SET claims = ARRAY[sender || '#' || nonce::text] WHERE claims IS NULL AND nonce IS NOT NULL;
UPDATE signed_digests SET fees = ARRAY[fee_cap, tip] WHERE fees IS NULL AND tip IS NOT NULL AND fee_cap IS NOT NULL;
DO $upgrade$
BEGIN
    IF to_regclass('nonce_claims') IS NOT NULL THEN
        INSERT INTO exclusive_claims (chain, claim, intent_id, kind)
            SELECT chain, sender || '#' || nonce::text, intent_id, kind FROM nonce_claims
            ON CONFLICT DO NOTHING;
        DROP TABLE nonce_claims;
    END IF;
END
$upgrade$;

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
