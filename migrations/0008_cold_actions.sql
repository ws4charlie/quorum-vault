-- P6-3 factory admin ceremony: the cold key administers the forwarder factory, so a cold request is either a refill (funds cold -> hot)
-- or a factory call (set the sweep destination, freeze, set the guardian, hand over the admin role). Both need the same offline
-- ceremony and the same tracking (export, import, broadcast, confirm), so they share the table. A factory call moves no funds: amount 0.

ALTER TABLE refills
    ADD COLUMN kind  text NOT NULL DEFAULT 'refill',   -- refill | set-destination | freeze | set-guardian | transfer-admin | accept-admin
    ADD COLUMN param text;                              -- the address argument of a factory call

ALTER TABLE refills DROP CONSTRAINT refills_amount_check;
ALTER TABLE refills ADD CONSTRAINT refills_amount_check CHECK ((kind = 'refill' AND amount > 0) OR (kind <> 'refill' AND amount = 0));
