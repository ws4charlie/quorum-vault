-- P6-1 hot to cold: when a hot shard holds more than its high-water mark, the excess moves to the cold address.
-- A cold move is a transfer out of a hot address (like a withdrawal) booked through a clearing account (like a sweep).
-- Business-zone state only: the destination is pinned in the signing zone's config, not here.

CREATE TABLE cold_moves (
    id             text PRIMARY KEY,
    chain          text NOT NULL,
    asset          text NOT NULL,
    partition_id   text NOT NULL REFERENCES partitions (id),
    to_address     text NOT NULL,                         -- the cold address the business config named; the signing zone checks it again
    amount         numeric(78,0) NOT NULL CHECK (amount > 0),
    status         text NOT NULL CHECK (status IN ('planned', 'signing', 'broadcast', 'confirmed', 'failed')),
    tx_hash        text,
    job_id         text,
    fee            numeric(78,0),
    failure_reason text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- At most one open move per hot partition and asset (the partition id already names the asset; kept for clarity).
CREATE UNIQUE INDEX cold_moves_one_open ON cold_moves (partition_id, asset) WHERE status NOT IN ('confirmed', 'failed');
CREATE INDEX cold_moves_open ON cold_moves (status) WHERE status NOT IN ('confirmed', 'failed');

-- Whether a hot partition is below its low-water mark right now, so the refill ALERT is raised once per outage and not on
-- every planner pass. Cleared when the balance is back above the mark.
CREATE TABLE hot_low_alerts (
    partition_id text PRIMARY KEY REFERENCES partitions (id),
    since        timestamptz NOT NULL DEFAULT now()
);
