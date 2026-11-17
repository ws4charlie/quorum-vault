-- Bitcoin withdrawal batches: one transaction that pays several withdrawals. Batching is off by default; these tables stay empty until it is turned on.

-- A batch is sealed from the head of one hot shard's queue (oldest approved first), gets its coins and its sign job when it is built, is broadcast,
-- and ends confirmed (every member booked once, by its output of the transaction), cancelled (a cancel of the whole batch confirmed: the members
-- return to the queue) or discarded (nothing was ever signed: the coins were released and the members returned to the queue).
CREATE TABLE btc_batches (
    id               text PRIMARY KEY,
    chain            text NOT NULL,
    partition_id     text NOT NULL,
    status           text NOT NULL CHECK (status IN ('sealed', 'signing', 'broadcast', 'confirmed', 'cancelled', 'discarded')),
    job_id           text,
    tx_hash          text,                    -- the first broadcast attempt, then the one that confirmed
    cancel_tx        text,                    -- the cancel that confirmed (status cancelled)
    resend_held      boolean NOT NULL DEFAULT false, -- the output of the cancel is held for the members that return (btc_utxos owner 'resend')
    cancel_requested boolean NOT NULL DEFAULT false, -- an operator asked to cancel the whole batch
    fee              numeric(78,0),
    reason           text,
    sealed_at        timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX btc_batches_open ON btc_batches (chain, partition_id) WHERE status IN ('sealed', 'signing', 'broadcast');

-- The members of a batch in payment order: position i is output i (vout) of its transaction. fee_share is set when the batch confirms (the real fee
-- split by btc.FeeShares, summing to the fee). resend_of names the cancelled batch the member was in before, when it was; the new batch spends an
-- output of that batch's cancel.
CREATE TABLE btc_batch_items (
    batch_id      text NOT NULL REFERENCES btc_batches (id),
    withdrawal_id text NOT NULL REFERENCES withdrawals (id),
    position      integer NOT NULL CHECK (position >= 0),
    vout          integer NOT NULL CHECK (vout >= 0),
    amount        numeric(78,0) NOT NULL CHECK (amount > 0),
    fee_share     numeric(78,0),
    resend_of     text,
    PRIMARY KEY (batch_id, withdrawal_id),
    UNIQUE (batch_id, position)
);
CREATE INDEX btc_batch_items_withdrawal ON btc_batch_items (withdrawal_id);

-- queued_at is when a withdrawal entered its shard's batch queue (after approval and the hot reserve): the queue is ordered by it, then by id. batch_id
-- is the batch it is in now (null while it waits). resend_of is the cancelled batch whose cancel output the next batch must spend for it.
-- batch_refusals counts the batches the signing zone refused with this member in them.
ALTER TABLE withdrawals ADD COLUMN queued_at timestamptz;
ALTER TABLE withdrawals ADD COLUMN batch_id text;
ALTER TABLE withdrawals ADD COLUMN resend_of text;
ALTER TABLE withdrawals ADD COLUMN batch_refusals integer NOT NULL DEFAULT 0;
CREATE INDEX withdrawals_queue ON withdrawals (partition_id, queued_at, id) WHERE queued_at IS NOT NULL AND batch_id IS NULL AND status NOT IN ('confirmed', 'failed');
