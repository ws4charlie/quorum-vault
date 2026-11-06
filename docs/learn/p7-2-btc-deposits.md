# P7-2 — Bitcoin deposits

A customer gets a Bitcoin address, pays it, and is credited once, after enough depth, through the same ledger as EVM. Nothing leaves
the address yet. Family `btc`, package [internal/chain/btc](../../internal/chain/btc).

## Addresses

The core's config holds `chain.btc.account_xpub`, the public key of the account node m/84'/coin'/0' (coin 0 on mainnet, 1 on every
test network) of the hot MPC keyset. You get it once from mpc-party `Node` with the hardened path `[84, coin, 0]` and build the xpub
with `btc.XpubFromNode(network, publicKey, chainCode, parentPublicKey)` (the parent, `[84, coin]`, only supplies the fingerprint).
The core then derives account/0/index offline, with no key and no MPC, and encodes the key as a bech32 P2WPKH address.

Each customer gets the next unused derivation index of the chain, under a lock
([ensureIndexedAddress](../../internal/custody/customers.go)); migration 0012 makes the index unique per chain.

**The assumption everything rests on** is tested on real mpc-party: for six indices, on the regtest and the mainnet account path,
the address from the xpub equals the P2WPKH of the public key `Derive` returns at `[0, index]` (`TestXpubAddressesEqualMPCDerivedKeys`).
cb-mpc's HD is BIP32-compatible. A second test checks the derivation against the BIP84 vector.

A config whose xpub belongs to another network (its version bytes), or whose hot address does not decode on the network, refuses to
start; so does a node on another network.

## Scanning

`Scan(from)` reads whole blocks with `getblock` verbosity 2 from `from` up to the safe head, tip minus confirmations plus one, and at
most `batch_blocks` (default 100) per call, so a long catch-up is many short activities. It matches every output that has an address
against `deposit_addresses` (one query per block). `OP_RETURN` and other scripts without an address are ignored. Amounts are read from
the node's decimal text into satoshis with no floating point. Dedup key `chain:txid:vout`, so two outputs of one transaction are two
deposits; a rescan of the same blocks finds the same keys and credits nothing.

The custody service applies a result in one transaction: deposits, the block hashes read, deferred deposits, the cursor.
Below `min_deposit` goes to suspense, as on EVM.

### Reorganizations

The table `scanned_blocks` holds the hash of every block read. Before reading, the scan checks that the node still has the block the
previous scan ended on, and that each block's parent is the block before it. Blocks are read only when they have `confirmations`
confirmations, so a mismatch means a reorganization deeper than that:

- `Scan` returns `chain.ErrReorgTooDeep`; the service writes a row to `scan_halts`, and the worker logs one
  `ALERT: scanning is halted and credits are kept`.
- Nothing is reversed. Credited deposits stay. The scan loop keeps running but does nothing while the row exists.
- The operator looks at the node and the books, decides, and deletes the row to resume. The cursor and the stored hashes are not
  changed by the halt: if the chain really was rewritten, they must be repaired by hand first (reset `chain_cursors.next_height`
  below the fork and delete the `scanned_blocks` rows above it; the dedup keys protect deposits that are still valid).

A reorganization within the safe depth never reaches the scanner: the replaced block was not read yet. If it held the payment, the
payment is credited when the block that replaced it (or the same payment, mined again) is `confirmations` deep.

### Coinbase

A coinbase output to a deposit address is spendable at 100 confirmations, so it is credited then. When a final block holds one that
is younger, `Scan` returns it as deferred with the height the scan must cover (`h + 100 - confirmations`); the service stores it in
`deferred_deposits` and credits it, once, in the scan that covers that height.

## What this task left out

`BuildWithdrawal`, `BuildSweep`, `BuildReplacement`, `BuildCancel`, `Assemble`, `Broadcast`, `Status`, `TxFee`, `MovedAssets`,
`Outcome` and `Reservation` return `chain.ErrNotSupported`; so do `Reader.Balance` and `Reader.TxBlock`. `Reconcile` skips the checks
that read balances (hot, cold, deposit addresses) and says so; the ledger invariants and the scan cursor check still run. Reading
balances (by `scantxoutset` or from the UTXO table of P7-4) is what those checks, settlement of withdrawals and sweeps will need.
The withdrawal API still validates destinations as EVM addresses (see the list in [p7-1-chain-seam.md](p7-1-chain-seam.md)).

## Running it

```bash
make btc-up infra-up softhsm mpc-build     # bitcoind regtest on 18443, Temporal, SoftHSM tokens, cb-mpc
make test-e2e-btc-deposits
```

The suite starts real `mpc-party` A and B, `qv-core` and `qv-worker` against that node and mines blocks itself. The CI job is
`e2e-btc-deposits`.
