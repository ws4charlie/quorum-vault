-- P6-4 hot shard rebalance: a hot shard below its target receives from the fullest sibling shard of the same pool.
-- A rebalance is a transfer out of the source's hot address (like a hot-to-cold move) booked through a clearing account.
-- Business-zone state only: the destination is checked again in the signing zone against its own list of hot shards.

CREATE TABLE rebalance_moves (
    id               text PRIMARY KEY,
    chain            text NOT NULL,
    asset            text NOT NULL,
    partition_id     text NOT NULL REFERENCES partitions (id),   -- the source shard (its key signs)
    to_partition_id  text NOT NULL REFERENCES partitions (id),   -- the receiving shard
    to_address       text NOT NULL,
    amount           numeric(78,0) NOT NULL CHECK (amount > 0),
    status           text NOT NULL CHECK (status IN ('planned', 'signing', 'broadcast', 'confirmed', 'failed')),
    tx_hash          text,
    job_id           text,
    fee              numeric(78,0),
    failure_reason   text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (partition_id <> to_partition_id)
);

-- At most one open rebalance per source shard and asset (the partition id already names the asset; kept for clarity).
CREATE UNIQUE INDEX rebalance_moves_one_open ON rebalance_moves (partition_id, asset) WHERE status NOT IN ('confirmed', 'failed');
-- And at most one open rebalance towards a receiving shard: it is fed once, not once per planner pass.
CREATE UNIQUE INDEX rebalance_moves_one_open_to ON rebalance_moves (to_partition_id, asset) WHERE status NOT IN ('confirmed', 'failed');
CREATE INDEX rebalance_moves_open ON rebalance_moves (status) WHERE status NOT IN ('confirmed', 'failed');

-- A token rebalance needs native gas on the source shard. The ALERT for a source without gas is raised once per outage.
CREATE TABLE rebalance_gas_alerts (
    partition_id text PRIMARY KEY REFERENCES partitions (id),
    since        timestamptz NOT NULL DEFAULT now()
);
