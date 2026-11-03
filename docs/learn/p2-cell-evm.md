# P2 — EVM cell: forwarders, deposits, nonces, offline verification

## What was built
| Piece | Where |
|---|---|
| `Forwarder`, `ForwarderFactory` (Solidity 0.8.26) + Foundry tests | `contracts/src`, `contracts/test` |
| Reproducible bytecode the Go code embeds | `internal/chain/evm/artifacts`, rebuilt by `contracts/build.sh` |
| Address derivation, scan, build/assemble/broadcast/status | `internal/chain/evm/{contracts,adapter,scan}.go` |
| Nonce manager and `Reconcile` | `internal/chain/evm/nonce.go` |
| Offline `Verifier` (`chain.TxVerifier`) | `internal/chain/evm/verify.go` |

## CREATE2 in one paragraph
`CREATE2` fixes a contract's address before it exists: `address = keccak256(0xff ++ factory ++ salt ++ keccak256(initcode))[12:]`. Anyone who knows the factory, the salt and the init code can compute it offline. That is why `DeriveDepositAddress` needs no RPC and no key: `PredictAddress` in Go is the same formula as `ForwarderFactory.predict` (a test compares them on chain). The salt is `keccak256(customer, index)` with a length prefix, so `("ab", 1)` and `("a", ...)` cannot collide.

## Why `destination` is in the init code
The forwarder's constructor argument is part of the init code, so it is part of the address. A different destination gives a different address. An attacker who deploys their own factory with their own destination cannot take over a customer's deposit address: the address they get for the same salt is different (`testDestinationCommittedInAddress`).

## Forwarders and the ETH/ERC-20 asymmetry
- **ETH**: the forwarder's `receive()` pushes ETH to the destination at once. Before deployment the address is just an empty account that accumulates ETH, and `deployAndFlush` sweeps it.
- **ERC-20**: tokens are bookkeeping inside the token contract. A transfer to the forwarder changes a mapping; the forwarder gets no callback and no chance to forward. Someone must call `flushTokens(token)` on it, so a sweep is a transaction, paid by the hot wallet.
- **USDT quirk**: USDT's `transfer` returns nothing. A `bool` return check on it reverts. `flushTokens` accepts "no return data" or "returns true" and rejects "returns false".
- **Anyone may call the flushes** because funds can only go to `destination`. There is no owner, no upgrade, no other function. Less code to audit, nothing to steal.

## Known limit: 21,000 gas
After deployment, `receive()` makes a CALL, so a plain send needs about 55-60k gas, not 21k. A 21,000-gas send reverts (status 0) and Scan does not count it. See `docs/measurements/evm.md`.

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
The signing gateway sits in a different trust zone from the business database. If the verifier asked the database or an RPC node what a transaction means, a compromised upstream could answer anything. So `Verifier` takes only `Config` (chain ID, factory, sweep destination, hot addresses, token addresses): it re-encodes the transaction from the payload, recomputes the digest, and compares destination, asset and amount to the intent that approvers signed. A sweep checks that the salt in the calldata resolves to the intent's source address, and that the intent's destination is the configured one. It cannot check the sweep **amount**: `flush` sends the whole balance, so the intent amount is informational for sweeps.

## Gotchas hit
- Mock tokens must emit `Transfer`; without it Scan sees nothing.
- A reverted deposit is a mined transaction with status 0; Scan must read receipts.
- anvil answers a duplicate broadcast with "already imported", not "already known".
- Block timestamps have 1-second resolution; the stuck test sleeps before mining.

## Quiz
1. Why does `DeriveDepositAddress` need neither RPC nor key?
2. What happens to ETH sent to a forwarder address before the contract exists?
3. Why can a plain `bool` check on `transfer` break with USDT?
4. Why does an ERC-20 deposit need a transaction to move on, but an ETH deposit does not?
5. Why can an attacker not hijack a deposit address with their own factory?
6. What does the row lock on `evm_nonces` guarantee, and what releases it?
7. Why does a rolled-back withdrawal leave no nonce gap?
8. What does `Reconcile` call a gap, and what a stuck allocation?
9. Why can the verifier not check a sweep's amount?
10. Why must the verifier not read the database or an RPC node?

<details><summary>Answers</summary>

1. The address is a pure function of factory, salt and init code (CREATE2); all three are known locally.
2. It sits on the empty address; `deployAndFlush` deploys and then `flushETH` sends it all to the destination.
3. USDT's `transfer` returns no data; decoding a bool from nothing reverts.
4. ETH arrival runs `receive()`; token balances are a mapping in the token and the forwarder is never called.
5. The destination is in the init code, so another destination means another address.
6. One writer per address; it is released at commit or rollback of the caller's transaction.
7. The counter bump and the allocation row roll back together, so the next caller gets the same nonce.
8. Gap: allocated nonce below the confirmed nonce that is not confirmed. Stuck: allocation unmoved for `StuckAfterBlocks` blocks at or above the confirmed nonce.
9. `flushETH`/`flushTokens` send the entire balance; the amount is not in the calldata.
10. Those are the data a compromised upstream controls; an offline check from signing-zone config cannot be lied to.
</details>
