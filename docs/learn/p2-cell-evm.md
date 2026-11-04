# P2 — EVM cell: forwarders, deposits, nonces, offline verification

## What was built
| Piece | Where |
|---|---|
| `Forwarder`, `ForwarderFactory` (Solidity 0.8.26) + Foundry tests (`forge test --isolate`) | `contracts/src`, `contracts/test` |
| Reproducible bytecode the Go code embeds | `internal/chain/evm/artifacts`, rebuilt by `contracts/build.sh` |
| Address derivation, scan, build/assemble/broadcast/status | `internal/chain/evm/{contracts,adapter,scan}.go` |
| Nonce manager and `Reconcile` | `internal/chain/evm/nonce.go` |
| Offline `Verifier` (`chain.TxVerifier`) | `internal/chain/evm/verify.go` |

## CREATE2 in one paragraph
`CREATE2` fixes a contract's address before it exists: `address = keccak256(0xff ++ factory ++ salt ++ keccak256(initcode))[12:]`. Anyone who knows the factory, the salt and the init code can compute it offline. That is why `DeriveDepositAddress` needs no RPC and no key: `PredictAddress` in Go is the same formula as `ForwarderFactory.predict` (a test compares them on chain). The salt is `keccak256(customer, index)` with a length prefix, so `("ab", 1)` and `("a", ...)` cannot collide.

## The destination lives in the factory
The forwarder has no constructor arguments: `factory` is its deployer. Its init code, and so its address, depends on the factory and the salt only, never on the destination. The factory stores `destination`; a forwarder asks the factory at flush time. Consequences:
- **Changeable without moving addresses.** The factory `admin` (a cold-key address) calls `setDestination`; every old deposit address then pays the new one. A stolen hot key cannot change it.
- **Freeze.** Destination zero makes every flush and `deployAndFlush` revert `SweepFrozen()`: funds stay where they are, nothing deploys. It reverts instead of returning, so a worker never records a sweep that moved nothing. The adapter returns `ErrSweepFrozen` from `BuildSweep` and `EstimateSweepFee` (read via `destination()`), so P3 can stop sweeping without treating it as an outage. A stale configuration (`SweepDestination` differs) returns `ErrDestinationMismatch`.
- **Two-step admin.** `transferAdmin` nominates; the nominee must `acceptAdmin`. Until then it has no power; afterwards the old admin has none.
- **Signing-zone config must follow.** The Verifier checks `intent.To == Config.SweepDestination`, a value it reads only from the signing zone's own config. When the cold key changes the destination, update that config by hand; until then every sweep is refused, which is the point.

## Forwarders and the ETH/ERC-20 asymmetry
- **ETH**: `receive()` is empty. ETH sits on the forwarder (or on the empty account before deployment) until a sweep calls `flushETH`. Deposits therefore look the same before and after deployment.
- **ERC-20**: tokens are bookkeeping inside the token contract. A transfer to the forwarder changes a mapping; the forwarder gets no callback. Someone must call `flushTokens(token)`, so a sweep is a transaction, paid by the hot wallet.
- **USDT quirk**: USDT's `transfer` returns nothing. A `bool` return check on it reverts. `flushTokens` accepts "no return data" or "returns true" and rejects "returns false".
- **Anyone may call the flushes** because funds can only go to the factory's destination. No owner, no upgrade, no delegatecall, no selfdestruct.

## Deposit gas
Empty `receive()` still has to run: after deployment a send with a limit of exactly 21,000 reverts; the smallest limit that works is 21,055 on anvil, and a 2,300-gas `transfer()` works. Before deployment 21,000 works. See `docs/measurements/evm.md`.

## Nonce lifecycle
```
BuildWithdrawal/BuildSweep (inside the caller's tx)
  lock evm_nonces row (FOR UPDATE)      one writer per address
  find allocation for (kind, id)?       yes -> same nonce; no -> next_nonce, then +1
  insert evm_nonce_allocations 'allocated'
commit or roll back with the withdrawal row   -> no gap, no reuse
Broadcast        -> 'broadcast', tx hash appended to tx_hash (comma list)
BuildReplacement -> same nonce, both fees >= +15%, row updated
Status/Reconcile -> 'confirmed' once a hash has a final receipt
```
Two things make this safe. The counter and the allocation row change in the same transaction as the caller's, so a rollback releases both. The row lock makes allocation a queue per address. The demo bug (T6) was the opposite: nonces chosen from a stale in-memory value, so two requests got the same nonce.

`Reconcile` reports **gaps** (an allocated nonce below the chain's confirmed nonce that was not confirmed: someone else used it, or a hash was lost) and **stuck** allocations (unmoved for `StuckAfterBlocks` blocks, measured by the timestamp of the block that many blocks behind head, because the table stores a time, not a height).

Replacement reads the original transaction body back from the node by hash, because the table stores no calldata. If the node has forgotten it, rebuild instead.

## Why the verifier must work offline
The signing gateway sits in a different trust zone from the business database. If the verifier asked the database or an RPC node what a transaction means, a compromised upstream could answer anything. So `Verifier` takes only `Config` (chain ID, factory, sweep destination, hot addresses, token addresses): it re-encodes the transaction from the payload, recomputes the digest, and compares destination, asset and amount to the intent that approvers signed. A sweep checks that the salt in the calldata resolves to the intent's source address (factory and salt only), and that the intent's destination is the configured one. It cannot check the sweep **amount**: `flush` sends the whole balance, so the intent amount is informational for sweeps.

## Fix round 1 additions
- **Fee cap.** The hot wallet pays gas and the approved intent does not contain it. `Config.MaxTxFeeWei` bounds `gas x max_fee_per_gas`; `Verify` rejects above it (a huge priority fee could otherwise be collected by a block producer the attacker controls). `BuildReplacement` and `BuildCancel` refuse to build a bump the gateway would refuse.
- **Replacement from our own data.** Migration 0003 stores the unsigned payload on the allocation and every broadcast attempt in `evm_tx_attempts`. A transaction the node evicted is the main case needing replacement, so the node cannot be the source.
- **Cancel.** Nonces are strictly sequential; one committed nonce whose job was refused blocks every later one. `BuildCancel` builds a zero-value 21,000-gas self-send at that nonce (fees bumped if it was broadcast); intent kind `cancel`. The allocation becomes `cancelled` when it confirms.
- **One-shot sweeper (rejected).** A constructor that sweeps and self-destructs worked on real transactions, but it relies on a deprecated opcode (if a fork stops deleting the account the address is stuck for good). The final design keeps a persistent forwarder and gets the changeable destination from the factory.

## Gotchas hit
- Mock tokens must emit `Transfer`; without it Scan sees nothing.
- A reverted deposit is a mined transaction with status 0; Scan must read receipts.
- anvil answers a duplicate broadcast with "already imported", not "already known".
- Block timestamps have 1-second resolution; the stuck test sleeps before mining.

## Quiz
1. Why does `DeriveDepositAddress` need neither RPC nor key?
2. What happens to ETH sent to a forwarder address, before and after the contract exists?
3. Why can a plain `bool` check on `transfer` break with USDT?
4. Why does an ERC-20 deposit need a transaction to move on, but an ETH deposit does not?
5. Why can an attacker not hijack a deposit address with their own factory?
6. What does the row lock on `evm_nonces` guarantee, and what releases it?
7. Why does a rolled-back withdrawal leave no nonce gap?
8. What does `Reconcile` call a gap, and what a stuck allocation?
9. Why can the verifier not check a sweep's amount?
10. Why must the verifier not read the database or an RPC node?
11. Why does the Verifier cap `gas x max_fee_per_gas` although the intent never mentions fees?
12. Why is replacement built from stored data and not from the node?
13. What does `BuildCancel` produce, and what unblocks?
14. Why can the destination change without moving any deposit address, and who can change it?
15. What happens to a sweep when the destination is zero, and why a revert instead of a quiet return?
16. After a destination change, why are sweeps refused until the signing zone's config is updated?

<details><summary>Answers</summary>

1. The address is a pure function of factory, salt and init code (CREATE2); all three are known locally.
2. In both cases it sits there (empty `receive()`); a sweep (`deployAndFlush`) moves it to the destination.
3. USDT's `transfer` returns no data; decoding a bool from nothing reverts.
4. ETH arrival runs `receive()`; token balances are a mapping in the token and the forwarder is never called.
5. The address commits to the deploying factory (CREATE2), and funds only reach that factory's destination.
6. One writer per address; it is released at commit or rollback of the caller's transaction.
7. The counter bump and the allocation row roll back together, so the next caller gets the same nonce.
8. Gap: allocated nonce below the confirmed nonce that is not confirmed. Stuck: allocation unmoved for `StuckAfterBlocks` blocks at or above the confirmed nonce.
9. `flushETH`/`flushTokens` send the entire balance; the amount is not in the calldata.
10. Those are the data a compromised upstream controls; an offline check from signing-zone config cannot be lied to.
11. The hot wallet pays it; a tampered priority fee could pay an attacker-controlled block producer while destination and amount look right.
12. Evicted transactions are the main case needing replacement, and the node no longer knows them.
13. A zero-value 21,000-gas self-send at the stuck nonce; every later nonce of that address can then mine.
14. The forwarder's init code has no arguments (address = factory + salt) and it reads the destination from the factory; only the cold-key admin can change it.
15. It is frozen: flushes revert `SweepFrozen()` and nothing deploys or moves; reverting means a worker can never record a sweep that moved nothing.
16. The Verifier compares `intent.To` with its own configured sweep destination, which it never learns from the business side.
</details>
