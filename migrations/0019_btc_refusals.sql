-- Bitcoin fee escalation. A replacement the node refuses is deleted (it must not hide the earlier attempts from the rebroadcast and the outcome
-- check), so the next fee bump would start again from the fee of the last accepted attempt and could build the same transaction for ever. This
-- row remembers, per owner, what the node refused: the highest fee refused for being too low (the next attempt pays more), how many replacements
-- were refused for that reason (they do not count against max_replacements), the last refusal that a higher fee does not cure (an ALERT), and the
-- fee market at the last refusal (the node's minimum mempool fee and its estimate, in sat/kvB), so that a fee held at a cap is tried again once the
-- market drops. Business-zone state only; one row per owner, removed when the owner settles or its reservation is released.
CREATE TABLE btc_refusals (
    chain         text   NOT NULL,
    owner_kind    text   NOT NULL,
    owner_id      text   NOT NULL,
    refused_fee   bigint NOT NULL DEFAULT 0 CHECK (refused_fee >= 0),
    fee_refusals  int    NOT NULL DEFAULT 0 CHECK (fee_refusals >= 0),
    other_refusal text   NOT NULL DEFAULT '',
    mempool_min   bigint NOT NULL DEFAULT 0,
    estimate      bigint NOT NULL DEFAULT 0,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain, owner_kind, owner_id)
);
