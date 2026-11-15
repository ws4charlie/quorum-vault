-- P8-8: on Solana a refill signs its own durable nonce of the cold address, so a SOL refill and a token refill can be open at the same time (one per
-- asset). On EVM and Bitcoin the cold address has one account nonce or one set of outputs, and two exported requests would pick the same one: they keep
-- one open refill per cold address.
ALTER TABLE refills ADD COLUMN exclusive boolean NOT NULL DEFAULT true;   -- true: one open refill per cold address; false: one per cold address and asset

DROP INDEX refills_one_open;
CREATE UNIQUE INDEX refills_one_open ON refills (chain, cold_address) WHERE status NOT IN ('confirmed', 'failed') AND exclusive;
CREATE UNIQUE INDEX refills_one_open_per_asset ON refills (chain, cold_address, asset) WHERE status NOT IN ('confirmed', 'failed');
