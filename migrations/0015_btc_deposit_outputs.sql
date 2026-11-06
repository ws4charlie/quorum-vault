-- Bitcoin: deposit outputs live in btc_utxos too.
--
-- 0013 said only hot outputs live here. That is no longer so: an output paid to a customer's deposit address enters this table in the
-- scan transaction that credits it, marked deposit = true, with the deposit address and the key path "0/<index>" that spends it, and the
-- partition of the shard a sweep pays into. Withdrawals select only deposit = false (a shard's own outputs); sweeps select only
-- deposit = true of one address. An output booked to suspense is never recorded: it stays where it is until a person reviews it.
ALTER TABLE btc_utxos ADD COLUMN deposit boolean NOT NULL DEFAULT false;
ALTER TABLE btc_utxos ADD COLUMN address text;
ALTER TABLE btc_utxos ADD CONSTRAINT btc_utxos_deposit_address CHECK ((NOT deposit) OR address IS NOT NULL);
CREATE INDEX btc_utxos_deposit_available ON btc_utxos (chain, address, created_at, txid, vout) WHERE deposit AND status = 'available';
