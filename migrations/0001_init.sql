-- quorum-vault initial schema. Owned by T0; other tasks ask the lead for changes.

CREATE TABLE wallets (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL UNIQUE,
    tier       text NOT NULL CHECK (tier IN ('hot', 'cold')),
    backend    text NOT NULL CHECK (backend IN ('hsm', 'mpc')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE keys (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id    uuid NOT NULL REFERENCES wallets(id),
    version      int NOT NULL,
    curve        text NOT NULL,
    backend      text NOT NULL CHECK (backend IN ('hsm', 'mpc')),
    purpose      text NOT NULL DEFAULT '',
    state        text NOT NULL CHECK (state IN ('active', 'sign_only', 'retired')),
    hsm_label    text,
    hsm_key_id   bytea,
    mpc_key_ref  text,
    public_key   bytea NOT NULL,
    address      text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    sign_only_at timestamptz,
    retired_at   timestamptz,
    UNIQUE (wallet_id, version)
);

-- At most one active key per wallet.
CREATE UNIQUE INDEX keys_one_active_per_wallet ON keys (wallet_id) WHERE state = 'active';

CREATE TABLE policies (
    wallet_id               uuid PRIMARY KEY REFERENCES wallets(id),
    daily_limit_wei         numeric(78,0) NOT NULL,
    per_tx_limit_wei        numeric(78,0) NOT NULL,
    approval_threshold_wei  numeric(78,0) NOT NULL,
    velocity_max_tx         int NOT NULL,
    velocity_window_seconds int NOT NULL,
    required_approvals      int NOT NULL,
    updated_at              timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE allowlist (
    wallet_id  uuid NOT NULL REFERENCES wallets(id),
    address    text NOT NULL, -- lowercase 0x-hex
    label      text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (wallet_id, address)
);

CREATE TABLE sign_requests (
    id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id                uuid NOT NULL REFERENCES wallets(id),
    key_id                   uuid NOT NULL REFERENCES keys(id),
    chain_id                 bigint NOT NULL,
    to_address               text NOT NULL,
    value_wei                numeric(78,0) NOT NULL,
    data                     bytea,
    nonce                    bigint NOT NULL,
    gas_limit                bigint NOT NULL,
    max_fee_per_gas          numeric(78,0) NOT NULL,
    max_priority_fee_per_gas numeric(78,0) NOT NULL,
    requester                text NOT NULL,
    status                   text NOT NULL CHECK (status IN
        ('pending_approval', 'approved', 'rejected', 'denied', 'signing', 'signed', 'failed')),
    decision                 jsonb,
    signature                bytea,
    raw_tx                   bytea,
    tx_hash                  text,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sign_requests_wallet_created ON sign_requests (wallet_id, created_at);

CREATE TABLE approvals (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id uuid NOT NULL REFERENCES sign_requests(id),
    approver   text NOT NULL,
    approve    boolean NOT NULL,
    comment    text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (request_id, approver)
);

-- Hash-chained audit log. No foreign keys: it must outlive the rows it describes.
CREATE TABLE audit_log (
    seq        bigserial PRIMARY KEY,
    at         timestamptz NOT NULL,
    actor      text NOT NULL,
    type       text NOT NULL,
    request_id uuid,
    wallet_id  uuid,
    key_id     uuid,
    payload    jsonb,
    prev_hash  bytea NOT NULL,
    hash       bytea NOT NULL
);

CREATE INDEX audit_log_request ON audit_log (request_id);
CREATE INDEX audit_log_wallet ON audit_log (wallet_id);

-- Append-only: reject every UPDATE, DELETE and TRUNCATE, even from the table owner.
CREATE FUNCTION audit_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;

CREATE TRIGGER audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();
