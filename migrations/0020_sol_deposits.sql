-- Solana deposit addresses (kind 'ed25519') come from a key tree like Bitcoin's: one derivation index is handed out once per chain.
CREATE UNIQUE INDEX deposit_addresses_ed25519_index ON deposit_addresses (chain, derivation_index) WHERE kind = 'ed25519';
