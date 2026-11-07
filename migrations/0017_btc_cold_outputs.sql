-- Bitcoin: outputs of the cold address live in btc_utxos too, marked cold.
--
-- A cold output has address = the cold address and no partition (a pool's cold address serves its shards, and the ledger keeps the cold accounts per
-- shard), so hot selection (by partition) and sweep selection (deposit = true) never see it. It is recorded when the books settle a transaction of
-- ours that pays the cold address (a move to cold, or the change of a refill) and by the scan, at safe depth, for money put there from outside. Only a
-- refill spends it.
ALTER TABLE btc_utxos ADD COLUMN cold boolean NOT NULL DEFAULT false;
ALTER TABLE btc_utxos ADD CONSTRAINT btc_utxos_cold_address CHECK ((NOT cold) OR address IS NOT NULL);
ALTER TABLE btc_utxos ADD CONSTRAINT btc_utxos_cold_not_deposit CHECK (NOT (cold AND deposit));
CREATE INDEX btc_utxos_cold_available ON btc_utxos (chain, address, created_at, txid, vout) WHERE cold AND status = 'available';

-- Outputs that confirmed to-cold moves put on the cold address before this migration have no row. Pick them up from the attempts, for the moves that
-- have exactly one transaction (the payment is output 0 of it): with a replacement in the history it cannot be known here which one confirmed, so
-- those are left for Reconcile, which reports a cold output on chain that the table does not hold.
INSERT INTO btc_utxos (chain, txid, vout, value, partition_id, path, cold, address)
SELECT a.chain, a.txid, 0, (a.payload->'outputs'->0->>'value')::bigint, '', '', true, a.payload->'outputs'->0->>'address'
FROM btc_attempts a
JOIN cold_moves m ON m.chain = a.chain AND m.id = a.owner_id
WHERE a.owner_kind = 'to-cold' AND a.kind = 'send' AND a.broadcast_at IS NOT NULL AND m.status = 'confirmed'
  AND (SELECT count(*) FROM btc_attempts b WHERE b.chain = a.chain AND b.owner_kind = 'to-cold' AND b.owner_id = a.owner_id AND b.kind = 'send') = 1
ON CONFLICT DO NOTHING;
