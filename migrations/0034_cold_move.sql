-- K7b: a cold-to-cold move (a cold key replacement) moves funds from the old cold address to the new one. It goes through the refills table:
-- the same ceremony, export, import, broadcast and tracking. Unlike a factory call it carries an amount.
ALTER TABLE refills DROP CONSTRAINT refills_amount_check;
ALTER TABLE refills ADD CONSTRAINT refills_amount_check CHECK ((kind IN ('refill', 'cold-move') AND amount > 0) OR (kind NOT IN ('refill', 'cold-move') AND amount = 0));
