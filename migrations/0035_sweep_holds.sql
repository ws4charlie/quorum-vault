-- Unswept-note: a credited deposit address whose funds are worth less than the sweep rule asks (value < max(min_sweep, k x fee)) stays where it is. The planner
-- writes one row per such (chain, address, asset) at every pass, with what it saw, and removes it when the address is swept or empties. The row is a
-- reading for operators (the reconcile output, the metrics): it moves no money and no rule reads it.
CREATE TABLE sweep_holds (
    chain       text    NOT NULL,
    address     text    NOT NULL,
    asset       text    NOT NULL,
    amount      numeric(78,0) NOT NULL,           -- unswept credited funds, in the asset's base units
    value       numeric(78,0) NOT NULL,           -- the same in the rule's common unit (amount x price)
    fee         numeric(78,0),                    -- the fee estimate of the sweep, same unit; NULL when none was asked (under min_sweep) or the chain gave none (fee_cap)
    threshold   numeric(78,0),                    -- max(min_sweep, k x fee); NULL for fee_cap
    cause       text NOT NULL CHECK (cause IN ('fee', 'min_sweep', 'fee_cap')),  -- fee: reached min_sweep, the fee alone holds it; min_sweep: under the floor; fee_cap: the chain offers no sweep of it now (Bitcoin: the fee rate is over the cap, or the outputs cost more than they carry)
    since       timestamptz NOT NULL DEFAULT now(),  -- the first pass that held it, kept while it stays held
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain, address, asset)
);

GRANT SELECT ON sweep_holds TO qv_core;
GRANT SELECT, INSERT, UPDATE, DELETE ON sweep_holds TO qv_worker;
