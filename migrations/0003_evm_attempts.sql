-- P2 fix 1: replacement and cancel rebuild from stored data, never from the node.
-- evm_nonce_allocations.payload is the latest unsigned payload built for the nonce;
-- evm_nonce_allocations.tx_hash is only the latest broadcast hash. Every broadcast
-- attempt (including replaced ones) is a row in evm_tx_attempts.
ALTER TABLE evm_nonce_allocations ADD COLUMN payload jsonb;

CREATE TABLE evm_tx_attempts (
    tx_hash    text PRIMARY KEY,
    chain      text NOT NULL,
    address    text NOT NULL,
    nonce      bigint NOT NULL CHECK (nonce >= 0),
    kind       text NOT NULL DEFAULT 'send' CHECK (kind IN ('send', 'cancel')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX evm_tx_attempts_nonce ON evm_tx_attempts (chain, address, nonce);
