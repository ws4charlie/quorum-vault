-- Key replacement, business side (K2b; docs/key-replacement.md).
--
-- keysets.successor: the generation that a draining (or compromised) generation empties into. It is set when the generation starts draining or is
-- marked compromised, mirrors the signed record of the signing zone (the zone decides from its own record, the core only plans from this one), and
-- is NULL for any generation that is not leaving. Null on every row that exists today: nothing changes for a shard with one generation.
ALTER TABLE keysets ADD COLUMN IF NOT EXISTS successor integer CHECK (successor IS NULL OR successor >= 1);
-- keysets.dust_written_off: the native amount that stayed at the address of a retired generation (what the last transfer's gas needed) and was written
-- off as a cost at retirement, so Reconcile expects exactly that much at the retired address and flags anything more.
ALTER TABLE keysets ADD COLUMN IF NOT EXISTS dust_written_off numeric(78,0);

-- drain_moves: one transfer of one asset from a draining generation's address to its successor's address (EVM). Like a rebalance it moves money
-- between two addresses of the same shard, so the shard's ledger account does not change; only the gas is booked, as a cost. At most one drain move
-- is open per shard and source generation, so a generation empties one asset at a time and a crash cannot make two transfers of the same asset.
CREATE TABLE IF NOT EXISTS drain_moves (
    id               text PRIMARY KEY,
    chain            text NOT NULL,
    shard_id         text NOT NULL,
    from_generation  integer NOT NULL,
    to_generation    integer NOT NULL,
    from_address     text NOT NULL,
    to_address       text NOT NULL,
    asset            text NOT NULL,
    partition_id     text NOT NULL REFERENCES partitions (id),   -- the shard's partition of the asset (the key that signs is the source generation's)
    amount           numeric(78,0) NOT NULL CHECK (amount > 0),
    status           text NOT NULL CHECK (status IN ('planned', 'signing', 'broadcast', 'confirmed', 'failed')),
    tx_hash          text,
    job_id           text,
    fee              numeric(78,0),
    failure_reason   text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (shard_id, from_generation) REFERENCES keysets (shard_id, generation),
    FOREIGN KEY (shard_id, to_generation) REFERENCES keysets (shard_id, generation),
    CHECK (from_generation <> to_generation)
);
CREATE UNIQUE INDEX IF NOT EXISTS drain_moves_one_open ON drain_moves (shard_id, from_generation) WHERE status NOT IN ('confirmed', 'failed');
CREATE INDEX IF NOT EXISTS drain_moves_open ON drain_moves (status) WHERE status NOT IN ('confirmed', 'failed');

-- keyset_drains: what the planner found at its last pass for a generation that is leaving: moving (a move is open), waiting (why: the signing zone
-- refused or delays, the successor has no gas, a read failed), or drained (nothing above dust is left; retiring is an operator step).
CREATE TABLE IF NOT EXISTS keyset_drains (
    shard_id    text        NOT NULL,
    generation  integer     NOT NULL,
    state       text        NOT NULL CHECK (state IN ('moving', 'waiting', 'drained')),
    reason      text        NOT NULL DEFAULT '',
    retry_after timestamptz,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (shard_id, generation),
    FOREIGN KEY (shard_id, generation) REFERENCES keysets (shard_id, generation)
);

-- Grants (migration 0030 style): the worker plans and drives drains, the core reads them for its admin API and writes nothing here.
GRANT SELECT ON drain_moves, keyset_drains TO qv_core;
GRANT SELECT, INSERT, UPDATE ON drain_moves, keyset_drains TO qv_worker;
