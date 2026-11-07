-- P7-6d Bitcoin consolidation: a hot shard fed by many small outputs merges the smallest into one, so the shard stays spendable within max_inputs.
-- A consolidation spends outputs of one hot shard and pays one output back to the same shard, so no value moves: the ledger books only the network
-- fee, at settlement. Business-zone state only; the signing zone checks the shape of the transaction itself.

CREATE TABLE consolidations (
    id             text PRIMARY KEY,
    chain          text NOT NULL,
    asset          text NOT NULL,
    partition_id   text NOT NULL REFERENCES partitions (id),
    amount         numeric(78,0) NOT NULL CHECK (amount > 0),   -- the sum of the inputs, before the fee (the signing zone requires exactly that)
    status         text NOT NULL CHECK (status IN ('planned', 'signing', 'broadcast', 'confirmed', 'failed')),
    tx_hash        text,
    job_id         text,
    fee            numeric(78,0),
    failure_reason text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- At most one open consolidation per hot partition: a second would compete with the first for the same small outputs.
CREATE UNIQUE INDEX consolidations_one_open ON consolidations (partition_id) WHERE status NOT IN ('confirmed', 'failed');
CREATE INDEX consolidations_open ON consolidations (status) WHERE status NOT IN ('confirmed', 'failed');
