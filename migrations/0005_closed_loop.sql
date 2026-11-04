-- P3b closed loop: scan cursor, sweep and withdrawal bookkeeping for the
-- workflows. Everything here is business-zone state; the ledger stays the
-- source of truth for money (see docs/learn/p3b-closed-loop.md).

-- Next block height Scan starts from, per chain. Advanced in the same
-- transaction that credits the deposits found below it.
CREATE TABLE chain_cursors (
    chain       text PRIMARY KEY,
    next_height bigint NOT NULL CHECK (next_height >= 0),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- One deposit address per customer per chain.
CREATE UNIQUE INDEX deposit_addresses_one_per_chain ON deposit_addresses (customer_id, chain);

ALTER TABLE deposits
    ADD COLUMN customer_id text REFERENCES customers (id),
    ADD COLUMN tx_hash     text,
    -- 'observed' = found by Scan; 'unexplained' = a sweep moved more than was ever
    -- seen as a deposit (e.g. ETH sent by an internal call) and it went to suspense.
    ADD COLUMN origin      text NOT NULL DEFAULT 'observed' CHECK (origin IN ('observed', 'unexplained'));

CREATE INDEX deposits_address_asset ON deposits (chain, address, asset) WHERE status IN ('credited', 'suspense');

ALTER TABLE sweeps
    ADD COLUMN job_id         text,
    ADD COLUMN moved          numeric(78,0),   -- what the chain says moved, of the swept asset
    ADD COLUMN fee            numeric(78,0),
    ADD COLUMN settled_height bigint,          -- chain head when the sweep was settled in the ledger
    ADD COLUMN trueup_done    boolean NOT NULL DEFAULT true,
    ADD COLUMN failure_reason text;

-- Never a second open sweep for one address and asset.
CREATE UNIQUE INDEX sweeps_one_open ON sweeps (chain, from_address, asset) WHERE status NOT IN ('confirmed', 'failed');

-- What each confirmed sweep actually moved out of a deposit address, per asset
-- (a token sweep also moves the address's ETH).
CREATE TABLE sweep_moves (
    sweep_id text NOT NULL REFERENCES sweeps (id),
    chain    text NOT NULL,
    address  text NOT NULL,
    asset    text NOT NULL,
    amount   numeric(78,0) NOT NULL CHECK (amount > 0),
    PRIMARY KEY (sweep_id, address, asset)
);

CREATE INDEX sweep_moves_address ON sweep_moves (chain, address, asset);

ALTER TABLE withdrawals
    ADD COLUMN requested_by    text NOT NULL DEFAULT '',
    ADD COLUMN idempotency_key text,
    ADD COLUMN request_hash    text,
    ADD COLUMN not_after       bigint,                         -- Unix seconds; part of the intent approvers sign
    ADD COLUMN approvals       jsonb NOT NULL DEFAULT '[]'::jsonb,  -- [{actor, signature}]
    ADD COLUMN hot_reserved    boolean NOT NULL DEFAULT false, -- liquidity set aside on the partition
    ADD COLUMN fee             numeric(78,0),
    ADD COLUMN failure_reason  text,
    ADD COLUMN job_id          text;

CREATE UNIQUE INDEX withdrawals_idempotency ON withdrawals (requested_by, idempotency_key) WHERE idempotency_key IS NOT NULL;
