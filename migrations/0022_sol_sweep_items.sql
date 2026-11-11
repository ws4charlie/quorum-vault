-- P8-6: a Solana sweep is one transaction that may take several deposit addresses of one asset. The sweep row names the first address
-- (from_address) and the total (amount); the items name every address with its amount and whether the sweep also closes the token account.
CREATE TABLE sweep_items (
    sweep_id      text NOT NULL REFERENCES sweeps (id),
    address       text NOT NULL,
    amount        numeric(78,0) NOT NULL CHECK (amount > 0),
    close_account boolean NOT NULL DEFAULT false,
    ord           integer NOT NULL DEFAULT 0,
    PRIMARY KEY (sweep_id, address)
);
