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
ALTER TABLE signed_intents ADD COLUMN IF NOT EXISTS partition_id text;
-- A batch (one Bitcoin transaction paying several withdrawals) is one row under its own id, which holds the claims and the digests. Each member
-- withdrawal gets a row of its own too (kind 'withdrawal', no claims, batch_id = the batch), written when the batch is first reserved: the rows count
-- towards the hourly rate and the daily cap like any withdrawal, and the primary key makes a withdrawal id usable once, in one batch.
ALTER TABLE signed_intents ADD COLUMN IF NOT EXISTS batch_id text;
ALTER TABLE exclusive_claims ADD COLUMN IF NOT EXISTS pin text NOT NULL DEFAULT '';
ALTER TABLE signed_digests ADD COLUMN IF NOT EXISTS tx_identity text;
CREATE INDEX IF NOT EXISTS signed_digests_identity ON signed_digests (tx_identity) WHERE tx_identity IS NOT NULL;

-- The change of a transaction the zone signed (Bitcoin), as the zone itself parsed it: the facts a CPFP child is judged against (its size and fee, which output is
-- the change and what it holds). One row per transaction identity; written when the transaction's first digest is reserved, only for the intents that keep a
-- change (a withdrawal, a hot-to-cold move, a batch).
CREATE TABLE IF NOT EXISTS signed_parents (
    chain        text NOT NULL,
    txid         text NOT NULL,
    intent_id    text NOT NULL REFERENCES signed_intents (intent_id),
    partition_id text NOT NULL,
    vsize        bigint NOT NULL,
    fee          bigint NOT NULL,
    change_vout  integer NOT NULL,
    change_value bigint NOT NULL,
    PRIMARY KEY (chain, txid)
);

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

-- The operators' preferred signing pair for the 2-of-3 keysets (see route.go). Every row carries the signatures of configured, enabled approvers
-- over (pair, seq, signed_at); the gateway checks them again every time it reads a row, so a row written by anyone else is ignored. Append-only.
CREATE TABLE IF NOT EXISTS mpc_route_changes (
    seq        bigint PRIMARY KEY,
    pair       text NOT NULL,
    signed_at  bigint NOT NULL,
    signatures jsonb NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER mpc_route_changes_no_update_delete
    BEFORE UPDATE OR DELETE ON mpc_route_changes
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- Signed changes of the Bitcoin fee caps (see internal/chain/btc/feecaps.go). Every row carries the signatures of configured approvers over
-- (chain, caps, seq, signed_at); the zone checks them again every time it reads a row, so a row written by anyone else is ignored. Append-only.
CREATE TABLE IF NOT EXISTS btc_fee_cap_changes (
    chain           text   NOT NULL,
    seq             bigint NOT NULL CHECK (seq >= 1),
    max_tx_fee_sats bigint NOT NULL CHECK (max_tx_fee_sats > 0),
    max_fee_rate    bigint NOT NULL CHECK (max_fee_rate > 0),
    signed_at       bigint NOT NULL,
    signatures      jsonb  NOT NULL,
    applied_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain, seq)
);

CREATE OR REPLACE TRIGGER btc_fee_cap_changes_no_update_delete
    BEFORE UPDATE OR DELETE ON btc_fee_cap_changes
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- Signed changes of the approver set (see approvers.go). Every row carries the signatures of configured operators over (action, name, the approver
-- entry of an enrolment, seq, signed_at); the zone checks them again every time it reads the log, so a row written by anyone else is ignored. The
-- gateway and every cosigner keep their own copy. Append-only; seq is not unique on purpose, so a forged row cannot take a sequence number from a
-- real change.
CREATE TABLE IF NOT EXISTS approver_changes (
    id         bigserial PRIMARY KEY,
    seq        bigint NOT NULL CHECK (seq >= 1),
    action     text   NOT NULL,
    name       text   NOT NULL,
    approver   jsonb,
    signed_at  bigint NOT NULL,
    signatures jsonb  NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER approver_changes_no_update_delete
    BEFORE UPDATE OR DELETE ON approver_changes
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE OR REPLACE TRIGGER approver_changes_no_truncate
    BEFORE TRUNCATE ON approver_changes
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();

-- Signed changes of the keyset states of the hot shards (see keysets.go). Every row carries the signatures of configured operators over (action,
-- shard, generation, address, successor, caps, seq, signed_at); the zone checks them again every time it reads the log, so a row written by anyone
-- else is ignored. The gateway and every cosigner keep their own copy. Append-only; seq is not unique on purpose, so a forged row cannot take a
-- sequence number from a real change.
CREATE TABLE IF NOT EXISTS keyset_changes (
    id         bigserial PRIMARY KEY,
    seq        bigint NOT NULL CHECK (seq >= 1),
    action     text   NOT NULL,
    shard      text   NOT NULL,
    generation integer NOT NULL,
    address    text   NOT NULL DEFAULT '',
    successor  integer NOT NULL DEFAULT 0,
    caps       jsonb,
    signed_at  bigint NOT NULL,
    signatures jsonb  NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

-- How to sign with a candidate generation (see KeysetChange): empty when the change names none.
ALTER TABLE keyset_changes ADD COLUMN IF NOT EXISTS key_ref text NOT NULL DEFAULT '';
ALTER TABLE keyset_changes ADD COLUMN IF NOT EXISTS public_key text NOT NULL DEFAULT '';
ALTER TABLE keyset_changes ADD COLUMN IF NOT EXISTS window_seconds bigint NOT NULL DEFAULT 0;

CREATE OR REPLACE TRIGGER keyset_changes_no_update_delete
    BEFORE UPDATE OR DELETE ON keyset_changes
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE OR REPLACE TRIGGER keyset_changes_no_truncate
    BEFORE TRUNCATE ON keyset_changes
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();
