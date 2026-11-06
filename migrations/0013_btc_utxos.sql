-- Bitcoin: the cell's own spendable outputs and the transactions it built.

-- Only hot outputs live here (a shard's address). An output arrives from our own transaction (its change, recorded when that
-- transaction settles) or from outside (operator funding, picked up by the scan at safe depth). It is reserved inside the transaction that
-- builds a withdrawal, spent when that withdrawal settles, and given back to 'available' only when nothing was ever signed.
CREATE TABLE btc_utxos (
    chain        text    NOT NULL,
    txid         text    NOT NULL,
    vout         integer NOT NULL CHECK (vout >= 0),
    value        bigint  NOT NULL CHECK (value > 0),
    partition_id text    NOT NULL,
    path         text    NOT NULL,                      -- derivation path of the key that spends it, "1/0"
    status       text    NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'reserved', 'spent')),
    owner_kind   text,
    owner_id     text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain, txid, vout),
    CHECK ((status = 'available') = (owner_id IS NULL))
);
CREATE INDEX btc_utxos_available ON btc_utxos (chain, partition_id, created_at, txid, vout) WHERE status = 'available';
CREATE INDEX btc_utxos_owner ON btc_utxos (chain, owner_kind, owner_id);

-- Every transaction the cell built for an owner, with its txid (the txid does not depend on the witness, so it is known unsigned). A
-- row is created at build time; broadcast_at is set when it was handed to the node. Only broadcast attempts count as attempts.
CREATE TABLE btc_attempts (
    chain        text   NOT NULL,
    txid         text   NOT NULL,
    owner_kind   text   NOT NULL,
    owner_id     text   NOT NULL,
    kind         text   NOT NULL DEFAULT 'send' CHECK (kind IN ('send', 'cancel')),
    payload      jsonb  NOT NULL,
    fee          bigint NOT NULL CHECK (fee >= 0),
    created_at   timestamptz NOT NULL DEFAULT now(),
    broadcast_at timestamptz,
    PRIMARY KEY (chain, txid)
);
CREATE INDEX btc_attempts_owner ON btc_attempts (chain, owner_kind, owner_id);
