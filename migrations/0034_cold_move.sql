-- K7b: a cold-to-cold move (a cold key replacement) moves funds from the old cold address to the new one. It goes through the refills table:
-- the same ceremony, export, import, broadcast and tracking. Unlike a factory call it carries an amount.
ALTER TABLE refills DROP CONSTRAINT refills_amount_check;
ALTER TABLE refills ADD CONSTRAINT refills_amount_check CHECK ((kind IN ('refill', 'cold-move') AND amount > 0) OR (kind NOT IN ('refill', 'cold-move') AND amount = 0));

-- A Solana cold-to-cold move that closes nonce accounts sends their rent to the NEW cold address: the books record it as a credit, so the cold check
-- stays exact between the transaction being final and its booking.
ALTER TABLE sol_cold_ops ADD COLUMN credit numeric(78,0) NOT NULL DEFAULT 0;
