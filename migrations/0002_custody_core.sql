-- Phase 2 custody core: ledger, partitions, deposits, withdrawals, sweeps,
-- EVM nonces, sign jobs, outbox. Owned by P0; later tasks ask the lead for changes.
-- All amounts are NUMERIC(78,0) in the asset's base units (wei, satoshi, lamports).

CREATE TABLE assets (
    chain            text NOT NULL,
    symbol           text NOT NULL,
    decimals         int  NOT NULL CHECK (decimals >= 0),
    contract_address text,                      -- NULL for the chain's native asset
    min_deposit      numeric(78,0) NOT NULL DEFAULT 0 CHECK (min_deposit >= 0),
    enabled          boolean NOT NULL DEFAULT true,
    PRIMARY KEY (chain, symbol)
);

-- id is the canonical partition.Key string (entity/chain/asset/tier/pool/shard).
CREATE TABLE partitions (
    id     text PRIMARY KEY,
    entity text NOT NULL,
    chain  text NOT NULL,
    asset  text NOT NULL,
    tier   text NOT NULL CHECK (tier IN ('hot', 'cold')),
    pool   text NOT NULL,                       -- 'omnibus' or 'segregated:<client>'
    shard  int  NOT NULL CHECK (shard >= 0),
    UNIQUE (entity, chain, asset, tier, pool, shard),
    FOREIGN KEY (chain, asset) REFERENCES assets (chain, symbol)
);

CREATE TABLE customers (
    id         text PRIMARY KEY,
    entity     text NOT NULL,
    us_state   text,                            -- attribute only; never a partition dimension
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ledger_accounts (
    id             text PRIMARY KEY,
    kind           text NOT NULL CHECK (kind IN ('customer', 'hot', 'cold', 'clearing', 'suspense', 'fee')),
    chain          text NOT NULL,
    asset          text NOT NULL,
    customer_id    text REFERENCES customers (id),
    partition_id   text REFERENCES partitions (id),
    allow_negative boolean NOT NULL DEFAULT false,
    posted         numeric(78,0) NOT NULL DEFAULT 0,
    held           numeric(78,0) NOT NULL DEFAULT 0,
    FOREIGN KEY (chain, asset) REFERENCES assets (chain, symbol),
    CHECK (held >= 0),
    CHECK (allow_negative OR posted - held >= 0)
);

CREATE INDEX ledger_accounts_customer ON ledger_accounts (customer_id) WHERE customer_id IS NOT NULL;

-- id is the caller's idempotency key.
CREATE TABLE ledger_txns (
    id         text PRIMARY KEY,
    kind       text NOT NULL CHECK (kind IN ('transfer', 'hold', 'post', 'void')),
    metadata   jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ledger_entries (
    id         bigserial PRIMARY KEY,
    txn_id     text NOT NULL REFERENCES ledger_txns (id),
    account_id text NOT NULL REFERENCES ledger_accounts (id),
    amount     numeric(78,0) NOT NULL,          -- signed
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ledger_entries_txn ON ledger_entries (txn_id);
CREATE INDEX ledger_entries_account ON ledger_entries (account_id, id);

-- Append-only: reject every UPDATE, DELETE and TRUNCATE, even from the table owner.
CREATE FUNCTION ledger_entries_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ledger_entries is append-only';
END;
$$;

CREATE TRIGGER ledger_entries_no_update_delete
    BEFORE UPDATE OR DELETE ON ledger_entries
    FOR EACH ROW EXECUTE FUNCTION ledger_entries_append_only();

CREATE TRIGGER ledger_entries_no_truncate
    BEFORE TRUNCATE ON ledger_entries
    FOR EACH STATEMENT EXECUTE FUNCTION ledger_entries_append_only();

-- Double entry: at commit, the entries of every txn must sum to zero per (chain, asset).
CREATE FUNCTION ledger_entries_zero_sum() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    bad record;
BEGIN
    SELECT a.chain, a.asset, SUM(e.amount) AS total INTO bad
    FROM ledger_entries e
    JOIN ledger_accounts a ON a.id = e.account_id
    WHERE e.txn_id = NEW.txn_id
    GROUP BY a.chain, a.asset
    HAVING SUM(e.amount) <> 0
    LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION 'ledger txn % is unbalanced: % % sums to %', NEW.txn_id, bad.chain, bad.asset, bad.total
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER ledger_entries_zero_sum
    AFTER INSERT ON ledger_entries
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION ledger_entries_zero_sum();

CREATE TABLE ledger_holds (
    id                 text PRIMARY KEY,
    account_id         text NOT NULL REFERENCES ledger_accounts (id),
    counter_account_id text NOT NULL REFERENCES ledger_accounts (id),
    amount             numeric(78,0) NOT NULL CHECK (amount > 0),
    status             text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'posted', 'voided')),
    expires_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    settled_at         timestamptz
);

CREATE INDEX ledger_holds_pending ON ledger_holds (account_id) WHERE status = 'pending';

CREATE TABLE deposit_addresses (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id      text NOT NULL REFERENCES customers (id),
    chain            text NOT NULL,
    asset            text,                      -- NULL: address accepts every asset on the chain
    address          text NOT NULL,
    derivation_index bigint NOT NULL CHECK (derivation_index >= 0),
    kind             text NOT NULL CHECK (kind IN ('forwarder', 'xpub', 'ed25519')),
    deployed         boolean NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (chain, address)
);

CREATE INDEX deposit_addresses_customer ON deposit_addresses (customer_id);

-- dedup_key: chain:tx_hash:log_index (EVM), chain:txid:vout (BTC), chain:sig:ix:inner_ix (Solana).
CREATE TABLE deposits (
    id           text PRIMARY KEY,
    chain        text NOT NULL,
    asset        text NOT NULL,
    address      text NOT NULL,
    amount       numeric(78,0) NOT NULL CHECK (amount > 0),
    dedup_key    text NOT NULL UNIQUE,
    status       text NOT NULL CHECK (status IN ('seen', 'confirmed', 'credited', 'suspense', 'reorged')),
    block_height bigint,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX deposits_status ON deposits (status) WHERE status IN ('seen', 'confirmed');

CREATE TABLE withdrawals (
    id           text PRIMARY KEY,
    customer_id  text NOT NULL REFERENCES customers (id),
    chain        text NOT NULL,
    asset        text NOT NULL,
    to_address   text NOT NULL,
    amount       numeric(78,0) NOT NULL CHECK (amount > 0),
    partition_id text NOT NULL REFERENCES partitions (id),
    status       text NOT NULL CHECK (status IN
        ('requested', 'held', 'approved', 'signing', 'broadcast', 'confirmed', 'failed')),
    tx_hash      text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX withdrawals_customer ON withdrawals (customer_id, created_at);
CREATE INDEX withdrawals_open ON withdrawals (status) WHERE status NOT IN ('confirmed', 'failed');

CREATE TABLE sweeps (
    id              text PRIMARY KEY,
    chain           text NOT NULL,
    asset           text NOT NULL,
    from_address    text NOT NULL,
    to_partition_id text NOT NULL REFERENCES partitions (id),
    amount          numeric(78,0) NOT NULL CHECK (amount > 0),
    status          text NOT NULL CHECK (status IN ('planned', 'signing', 'broadcast', 'confirmed', 'failed')),
    tx_hash         text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sweeps_open ON sweeps (status) WHERE status NOT IN ('confirmed', 'failed');

-- One writer per address owns next_nonce; allocations are persisted in the
-- same transaction as the withdrawal/sweep that uses them.
CREATE TABLE evm_nonces (
    chain      text NOT NULL,
    address    text NOT NULL,
    next_nonce bigint NOT NULL CHECK (next_nonce >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain, address)
);

CREATE TABLE evm_nonce_allocations (
    chain                    text NOT NULL,
    address                  text NOT NULL,
    nonce                    bigint NOT NULL CHECK (nonce >= 0),
    owner_kind               text NOT NULL,     -- 'withdrawal' | 'sweep' | ...
    owner_id                 text NOT NULL,
    status                   text NOT NULL CHECK (status IN
        ('allocated', 'broadcast', 'confirmed', 'replaced', 'cancelled')),
    tx_hash                  text,
    max_fee_per_gas          numeric(78,0),
    max_priority_fee_per_gas numeric(78,0),
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain, address, nonce)
);

CREATE INDEX evm_nonce_allocations_owner ON evm_nonce_allocations (owner_kind, owner_id);

-- Work queue between the business zone and the signing gateway. id is the idempotency key.
CREATE TABLE sign_jobs (
    id            text PRIMARY KEY,
    partition_id  text NOT NULL REFERENCES partitions (id),
    key_ref       text NOT NULL,
    chain         text NOT NULL,
    intent        jsonb NOT NULL,           -- signjob.Intent; approvers sign its hash
    digest        bytea NOT NULL,
    payload       jsonb NOT NULL,
    approvals     jsonb NOT NULL DEFAULT '[]'::jsonb,
    status        text NOT NULL DEFAULT 'pending' CHECK (status IN
        ('pending', 'signing', 'done', 'rejected', 'failed')),
    signature     bytea,
    reject_reason text,
    locked_by     text,
    locked_at     timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sign_jobs_pending ON sign_jobs (created_at) WHERE status = 'pending';

-- Transactional outbox: written in the business transaction, published by a polling relay.
CREATE TABLE outbox (
    seq          bigserial PRIMARY KEY,
    id           uuid NOT NULL UNIQUE,
    topic        text NOT NULL,
    key          text NOT NULL,
    payload      jsonb NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz
);

CREATE INDEX outbox_unpublished ON outbox (seq) WHERE published_at IS NULL;
