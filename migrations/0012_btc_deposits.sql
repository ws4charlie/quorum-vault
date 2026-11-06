-- Chain-neutral scan state for chains that detect reorganizations by block hash (Bitcoin), deposits that are final but not yet
-- spendable (a coinbase output), and a stop for a scan that met a reorganization deeper than the safe depth.

-- The hash of every block a scan read, written in the same transaction as the deposits and the cursor. The next scan checks that
-- the chain still has the block it ended on.
CREATE TABLE scanned_blocks (
    chain      text   NOT NULL,
    height     bigint NOT NULL CHECK (height >= 0),
    hash       text   NOT NULL,
    scanned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain, height)
);

-- A deposit seen in a final block that is credited only once the scan has covered release_at.
CREATE TABLE deferred_deposits (
    dedup_key  text PRIMARY KEY,
    chain      text   NOT NULL,
    release_at bigint NOT NULL,
    deposit    jsonb  NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX deferred_deposits_release ON deferred_deposits (chain, release_at);

-- A scan that found the chain rewritten below the safe depth stops here. Credits stay. An operator looks, then deletes the row
-- (docs/learn/p7-2-btc-deposits.md).
CREATE TABLE scan_halts (
    chain  text PRIMARY KEY,
    reason text NOT NULL,
    at     timestamptz NOT NULL DEFAULT now()
);

-- One derivation index is handed out once per chain.
CREATE UNIQUE INDEX deposit_addresses_xpub_index ON deposit_addresses (chain, derivation_index) WHERE kind = 'xpub';
