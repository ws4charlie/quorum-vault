-- Signed changes of the Bitcoin fee caps (max_tx_fee_sats, max_fee_rate), as the core reads them (internal/chain/btc/feecaps.go). Every row carries
-- the signatures of configured approvers over (chain, caps, seq, signed_at); the core checks them again every time it reads, so a row written by
-- anyone else is ignored. Append-only. The signing zone keeps the same table in its guard database.
CREATE TABLE IF NOT EXISTS btc_fee_cap_changes (
    chain           text   NOT NULL,
    seq             bigint NOT NULL CHECK (seq >= 1),
    max_tx_fee_sats bigint NOT NULL CHECK (max_tx_fee_sats > 0),
    max_fee_rate    bigint NOT NULL CHECK (max_fee_rate > 0),
    signed_at       bigint NOT NULL,
    signatures      jsonb  NOT NULL,
    applied_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain, seq)
);

CREATE OR REPLACE TRIGGER btc_fee_cap_changes_no_update_delete
    BEFORE UPDATE OR DELETE ON btc_fee_cap_changes
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
