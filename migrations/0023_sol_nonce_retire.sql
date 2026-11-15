-- P8-8: a nonce account can be retired (taken out of the pool: no new allocation) and, once idle, closed so its rent comes back. A retired or closed
-- account is not created again by the pool setup.
ALTER TABLE sol_nonce_accounts ADD COLUMN retired_at timestamptz;
ALTER TABLE sol_nonce_accounts ADD COLUMN closed_at  timestamptz;
ALTER TABLE sol_nonce_accounts ADD COLUMN close_tx   text;   -- the signature of the close, recorded before it is sent: a crash after it can still be booked

-- The same for the nonce accounts of a cold address (they live on the chain and are not otherwise recorded here).
CREATE TABLE sol_cold_nonce_retired (
    chain      text NOT NULL,
    address    text NOT NULL,   -- the nonce account
    cold       text NOT NULL,   -- its authority: the cold address
    idx        integer NOT NULL CHECK (idx >= 0),
    retired_at timestamptz NOT NULL DEFAULT now(),
    closed_at  timestamptz,
    PRIMARY KEY (chain, address)
);

-- A cold setup or close, recorded before it is sent: between its being final and its cost being booked, Reconcile explains the cold address's balance from it.
CREATE TABLE sol_cold_ops (
    chain      text NOT NULL,
    signature  text NOT NULL,
    cold       text NOT NULL,
    kind       text NOT NULL,
    booked     boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chain, signature)
);
