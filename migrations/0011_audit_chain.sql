-- Tamper-evident audit on /v2. Business code writes audit events to the outbox (topic qv.audit) inside its own transaction;
-- one chainer (qv-relay) appends them to audit_log, once each (source_id). Applied once; the guard databases of the gateway
-- and the cosigner carry the same audit_log (gateway/store.sql).

ALTER TABLE outbox ADD COLUMN chained_at timestamptz;
CREATE INDEX outbox_unchained ON outbox (seq) WHERE topic = 'qv.audit' AND chained_at IS NULL;

-- Rows from before this migration were never chained; they stay as they are.
UPDATE outbox SET chained_at = now() WHERE topic = 'qv.audit';

-- An outbox row is evidence until it is chained: only the two bookkeeping columns may change, and nothing is deleted.
CREATE FUNCTION outbox_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'outbox rows are not deleted';
    END IF;
    IF NEW.seq IS DISTINCT FROM OLD.seq OR NEW.id IS DISTINCT FROM OLD.id OR NEW.topic IS DISTINCT FROM OLD.topic
       OR NEW.key IS DISTINCT FROM OLD.key OR NEW.payload IS DISTINCT FROM OLD.payload OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'outbox rows are immutable (only published_at and chained_at change)';
    END IF;
    IF OLD.chained_at IS NOT NULL AND NEW.chained_at IS DISTINCT FROM OLD.chained_at THEN
        RAISE EXCEPTION 'outbox chained_at is set once';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER outbox_no_edit
    BEFORE UPDATE OR DELETE ON outbox
    FOR EACH ROW EXECUTE FUNCTION outbox_immutable();

CREATE TRIGGER outbox_no_truncate
    BEFORE TRUNCATE ON outbox
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();

-- The outbox row an audit entry came from; a second chaining of the same row is refused by the database.
ALTER TABLE audit_log ADD COLUMN source_id uuid UNIQUE;

-- What core last saw of the forwarder factory, so a change (frozen, unfrozen) is recorded once.
CREATE TABLE factory_state (
    chain      text PRIMARY KEY,
    frozen     boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
