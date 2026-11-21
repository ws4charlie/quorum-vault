-- A Solana drain closes an empty token account of the old key (K4): that move names no amount. Everything else still moves something: the check now lets
-- amount be zero only for such a close step (its move ID is dr-token-close-...). Grants are unchanged (no new table).
ALTER TABLE drain_moves DROP CONSTRAINT IF EXISTS drain_moves_amount_check;
ALTER TABLE drain_moves ADD CONSTRAINT drain_moves_amount_check CHECK (amount > 0 OR (amount = 0 AND id LIKE 'dr-token-close-%'));
