-- P8-5: Solana withdrawals sign the value of a durable nonce. Each hot shard owns a small pool of nonce accounts (their addresses follow from
-- the shard, see sol.NonceAddress); one account carries at most one withdrawal in flight, as one EVM nonce does.
CREATE TABLE sol_nonce_accounts (
    chain       text NOT NULL,
    address     text NOT NULL,   -- the nonce account
    hot_address text NOT NULL,   -- its authority: the hot shard
    idx         integer NOT NULL CHECK (idx >= 0),
    PRIMARY KEY (chain, address)
);

-- One row per withdrawal (or other owner) that took a nonce account: the value it signed, the latest unsigned message built for it (a fee-bumped
-- version or a cancel replaces it), and how it ended. The partial unique index is the rule "never two in flight on one account".
CREATE TABLE sol_nonce_allocations (
    id          bigserial PRIMARY KEY,
    chain       text NOT NULL,
    address     text NOT NULL,   -- the nonce account
    hot_address text NOT NULL,
    nonce_value text NOT NULL,   -- base58 of the durable nonce every version of the owner signs
    owner_kind  text NOT NULL,
    owner_id    text NOT NULL,
    status      text NOT NULL CHECK (status IN ('allocated', 'broadcast', 'confirmed', 'cancelled', 'released')),
    payload     bytea NOT NULL,  -- the latest unsigned payload (JSON, the message)
    price       bigint NOT NULL CHECK (price >= 0),   -- its compute unit price, micro-lamports
    tx_hash     text,            -- the latest broadcast signature
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (chain, address) REFERENCES sol_nonce_accounts (chain, address)
);
CREATE UNIQUE INDEX sol_nonce_allocations_open ON sol_nonce_allocations (chain, address) WHERE status IN ('allocated', 'broadcast');
CREATE UNIQUE INDEX sol_nonce_allocations_owner ON sol_nonce_allocations (chain, owner_kind, owner_id) WHERE status IN ('allocated', 'broadcast', 'confirmed');

-- Every transaction ever broadcast for an allocation, replaced versions included: any of them may be the one that lands.
CREATE TABLE sol_tx_attempts (
    signature     text PRIMARY KEY,
    chain         text NOT NULL,
    allocation_id bigint NOT NULL REFERENCES sol_nonce_allocations (id),
    kind          text NOT NULL CHECK (kind IN ('send', 'cancel')),
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sol_tx_attempts_allocation ON sol_tx_attempts (allocation_id);
