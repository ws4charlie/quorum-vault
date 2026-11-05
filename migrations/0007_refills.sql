-- P6-2 cold to hot: a refill brings funds from the cold address back to a hot wallet that fell below its low-water mark.
-- It needs an offline ceremony, so a refill waits for people, perhaps for days. Business-zone state only: the offline signer's
-- own config decides what it will sign.

CREATE TABLE refills (
    id             text PRIMARY KEY,
    chain          text NOT NULL,
    asset          text NOT NULL,
    partition_id   text NOT NULL REFERENCES partitions (id),   -- the hot partition that gets the funds
    cold_address   text NOT NULL,
    to_address     text NOT NULL,                              -- the hot address
    amount         numeric(78,0) NOT NULL CHECK (amount > 0),
    -- requested: waiting for the ceremony; signed: the signed file was imported; broadcast: sent, waiting to mine
    status         text NOT NULL CHECK (status IN ('requested', 'signed', 'broadcast', 'confirmed', 'failed')),
    revision       integer NOT NULL DEFAULT 0,                 -- grows with every export (new nonce or fees)
    request        jsonb,                                      -- the request file as last exported
    request_hash   text,
    raw_tx         text,                                       -- the signed transaction, hex
    tx_hash        text,
    fee            numeric(78,0),
    failure_reason text,
    stuck_alerted  boolean NOT NULL DEFAULT false,             -- the "has not confirmed" ALERT was given
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- One open refill per cold address: the cold address has one nonce, and a second signed transaction at the same nonce
-- would be a second chance to pay.
CREATE UNIQUE INDEX refills_one_open ON refills (chain, cold_address) WHERE status NOT IN ('confirmed', 'failed');
CREATE INDEX refills_open ON refills (status) WHERE status NOT IN ('confirmed', 'failed');
