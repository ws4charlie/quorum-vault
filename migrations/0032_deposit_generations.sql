-- Deposit addresses know their key generation (K5 of key replacement, docs/key-replacement.md).
-- On Bitcoin and Solana every customer deposit address derives from the deposit key tree; replacing that key (K6) changes every address. Until now a customer had
-- one address per chain and nothing recorded which key it came from. From here an address belongs to a generation of the deposit tree (the keysets registry
-- holds the generations: shard id entity/chain/deposit-tree/0), a customer may hold one address per generation, and an address stays unique per chain.
-- Existing rows are generation 1: the key every deployment has today. derivation_index keeps its per-chain unique indexes (0012, 0020), so an index is never
-- reused across generations. Backward compatible: the previous release reads and inserts rows without the column (the default 1) as long as there is one generation.
ALTER TABLE deposit_addresses ADD COLUMN IF NOT EXISTS generation integer NOT NULL DEFAULT 1 CHECK (generation >= 1);

DROP INDEX IF EXISTS deposit_addresses_one_per_chain;
CREATE UNIQUE INDEX IF NOT EXISTS deposit_addresses_one_per_generation ON deposit_addresses (customer_id, chain, generation);

-- The scan and Reconcile read the watch list by chain and generation.
CREATE INDEX IF NOT EXISTS deposit_addresses_chain_generation ON deposit_addresses (chain, generation);
