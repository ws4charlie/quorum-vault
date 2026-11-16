-- Outbox retention. A published outbox row is only a copy once Kafka has it (and, for an audit row, once audit_log has it), so old
-- ones may go. The rule stays "evidence until chained, and not deleted by hand": a row leaves only through outbox_prune(), and
-- the trigger re-checks every row it deletes against a hard minimum age that no caller can lower.
--
-- Eligible: published_at is set, and for the audit topic chained_at is set too, and the row is older than the retention. Age runs
-- from the later of published_at and chained_at (published_at alone for other topics): the clock starts when the row stopped being
-- the only copy, not when the business change happened. audit_log is never touched.

-- Hard minimum: 7 days. Written in the trigger and in outbox_prune() (keep the two equal).
CREATE OR REPLACE FUNCTION outbox_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Only outbox_prune() sets this flag, and even with it the row must be published, chained (audit) and older than the minimum.
        IF current_setting('qv.outbox_prune', true) IS DISTINCT FROM 'on'
           OR OLD.published_at IS NULL
           OR (OLD.topic = 'qv.audit' AND OLD.chained_at IS NULL)
           OR GREATEST(OLD.published_at, OLD.chained_at) > now() - interval '7 days' THEN
            RAISE EXCEPTION 'outbox rows are not deleted';
        END IF;
        RETURN OLD;
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

-- Deletes at most max_rows eligible rows older than retention (never less than 7 days, whatever is passed) and returns how many.
CREATE FUNCTION outbox_prune(retention interval, max_rows int) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    n bigint;
BEGIN
    retention := GREATEST(retention, interval '7 days');
    max_rows := LEAST(GREATEST(max_rows, 1), 10000);
    PERFORM set_config('qv.outbox_prune', 'on', true);   -- this transaction only
    WITH doomed AS (
        SELECT seq FROM outbox
        WHERE published_at IS NOT NULL
          AND (topic <> 'qv.audit' OR chained_at IS NOT NULL)
          AND GREATEST(published_at, chained_at) < now() - retention
        ORDER BY seq LIMIT max_rows
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM outbox o USING doomed WHERE o.seq = doomed.seq;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('qv.outbox_prune', 'off', true);
    RETURN n;
END;
$$;

-- Callers need EXECUTE (the owner has it; grant it to the relay's role if that is another role).
REVOKE ALL ON FUNCTION outbox_prune(interval, int) FROM PUBLIC;
