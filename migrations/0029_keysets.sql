-- Keyset registry (K1 of key replacement, research/Key-replacement.md §6): which key generation serves each hot shard, in which state.
-- A shard is identified by its stable shard ID (entity/chain/pool/shard index, internal/partition ShardID), never by a key or an address,
-- so ledger accounts, holds and jobs keep pointing at the shard when its key changes. States: candidate -> active -> draining -> retired,
-- and compromised (from candidate, active or draining; it never leaves). The database allows at most one active generation per shard.
-- The core registers generation 1 of every configured shard as active at start (custody Bootstrap); nothing else writes this table yet.
CREATE TABLE IF NOT EXISTS keysets (
    shard_id         text        NOT NULL,
    generation       integer     NOT NULL CHECK (generation >= 1),
    key_ref          text        NOT NULL DEFAULT '',   -- the MPC keyset ID, when the process that registers it knows it
    address          text        NOT NULL,              -- the shard's address in the family's own form
    public_key       bytea,
    state            text        NOT NULL CHECK (state IN ('candidate', 'active', 'draining', 'retired', 'compromised')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    state_changed_at timestamptz NOT NULL DEFAULT now(),
    activated_at     timestamptz,
    draining_at      timestamptz,
    retired_at       timestamptz,
    compromised_at   timestamptz,
    PRIMARY KEY (shard_id, generation),
    UNIQUE (shard_id, address)
);

CREATE UNIQUE INDEX IF NOT EXISTS keysets_one_active_per_shard ON keysets (shard_id) WHERE state = 'active';
