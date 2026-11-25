-- x402 payment authorizations (docs/evm.md, "x402 authorizations"): an EIP-3009 transferWithAuthorization the hot wallet's key signs and a facilitator
-- submits on chain. It moves nothing when it is signed: it is a liability (a hold on the ledger account x402:<chain>:<asset>) until the token emits
-- AuthorizationUsed for it (the payment: the hold is posted to the hot account) or its validBefore has passed on a final block (released). Rows are
-- written by the core when an authorization is requested and settled by the worker's x402 pass; the rows explain the open holds to Reconcile.
CREATE TABLE x402_authorizations (
    id            text PRIMARY KEY,                           -- the caller's idempotency key (GC4 uses the credential_id)
    chain         text NOT NULL,
    asset         text NOT NULL,
    partition_id  text NOT NULL REFERENCES partitions (id),   -- the hot shard that pays
    payer         text NOT NULL,                              -- the hot address (EIP-55)
    payee         text NOT NULL,
    amount        numeric(78,0) NOT NULL CHECK (amount > 0),
    valid_after   bigint NOT NULL,                            -- seconds since the epoch; usable when valid_after < block time < valid_before
    valid_before  bigint NOT NULL,
    nonce         text NOT NULL CHECK (nonce ~ '^0x[0-9a-f]{64}$'),
    body_hash     bytea NOT NULL,                             -- of the request, so a repeat of an id with another body is refused
    job_id        text NOT NULL,
    since_block   bigint NOT NULL DEFAULT 0,                  -- a final block before any block the authorization can be used in: where the event search starts
    status        text NOT NULL CHECK (status IN ('requested', 'signed', 'used', 'expired', 'refused')),
    used_tx       text,
    used_block    bigint,
    reason        text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (chain, asset, payer, nonce)                       -- the token's nonce is used once per payer
);
CREATE INDEX x402_authorizations_open ON x402_authorizations (chain, asset, payer) WHERE status IN ('requested', 'signed');

GRANT SELECT, INSERT, UPDATE ON x402_authorizations TO qv_core;
GRANT SELECT, INSERT, UPDATE ON x402_authorizations TO qv_worker;
