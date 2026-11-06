-- Bitcoin: keep the signed raw transaction of a broadcast attempt, so a transaction the node forgot (a restart with an empty mempool, an
-- eviction) can be sent again, and remember when it was last sent so it is not sent on every poll.
ALTER TABLE btc_attempts ADD COLUMN raw bytea;
ALTER TABLE btc_attempts ADD COLUMN last_sent_at timestamptz;
