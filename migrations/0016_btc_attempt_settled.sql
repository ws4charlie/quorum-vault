-- Bitcoin: when the books settled an attempt (its inputs spent, its outputs recorded, the ledger moved). Reconcile uses it: an output of one of our
-- own transactions is not counted from the chain until the books have settled that transaction, and is counted afterwards (an output to a cold
-- address is never in the output table, so settlement is the only thing that tells them apart).
ALTER TABLE btc_attempts ADD COLUMN settled_at timestamptz;
