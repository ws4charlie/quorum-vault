# x402 payments from a hot wallet

An x402 service is paid with an EIP-3009 `transferWithAuthorization`: typed data (EIP-712) that the payer signs and the service's facilitator submits on chain. QuorumVault signs it with a hot-wallet key. Nothing leaves the wallet when it is signed, and the zone refuses every one until the payment credential check is installed (below).

## What the zone checks (intent kind `eip3009`)

The zone reads the typed data itself, recomputes the EIP-712 digest and signs only that digest. Everything is compared with what it decoded, never with a field beside the payload.

| Check | Where |
|:---|:---|
| Strict shape: no unknown field, no trailing data, the type definitions are exactly EIP-3009's, every number canonical | `internal/chain/evm/eip3009.go` |
| Domain: chain id is the zone's chain, verifying contract is a configured token with an `x402` entry, name and version are the configured ones | same |
| Payer (`from`) is the hot address of the job's partition, and that key generation may sign | same; `internal/gateway/keysets.go` |
| Payee, amount and token equal the intent's; value within `per_payment_limit` | same |
| `validBefore - validAfter` within `max_window_seconds`; `validBefore` in the future and at most `max_window_seconds` ahead of the zone's clock | same; `internal/gateway/decider.go` |
| The EIP-3009 nonce is a claim of the replay guard: the same nonce is never signed twice for the same token and payer, in the gateway's guard and in each cosigner's | `internal/gateway/decider.go` (claims) |
| The wallet is Gate-governed and the authorization carries a Gate credential that passes every check (window inside the credential's, replay record, fast lane) | `internal/gateway/gaterule.go` |

The signature is the 32-byte digest signed by the hot key, returned as `r`, `s` (big-endian, `s` in the lower half of the curve order) and `v` = 27 or 28, as USDC's `ecrecover` requires (`evm.SignatureRSV`).

## The Gate credential

The zone decodes the payment into `TxInfo.Payment` (`chain` as `eip155:<id>`, `asset` as the token address, `payee`, `amount`, `validAfter`, `validBefore`, `nonce`, `payer`) and checks the job's Gate credential against it, inside the replay guard's transaction, so the used credential id and the token nonce commit together ([spec](../gate-credential.md)). The rule is part of every decider; an authorization from a wallet that is not Gate-governed is refused with `wallet_not_gate_governed`. Which wallets are Gate-governed, and their limits, is the operator-signed [Gate setting](gate-setting.md).

## The USDC on Base Sepolia (chain 84532)

| Field | Value | Source |
|:---|:---|:---|
| Token | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` | Circle, USDC contract addresses: https://developers.circle.com/stablecoins/usdc-contract-addresses |
| EIP-712 name | `USDC` | `name()` of the contract, read with `eth_call` against `https://sepolia.base.org` on 2026-11-24 |
| EIP-712 version | `2` | `version()`, same read |
| Chain id | `84532` | `eth_chainId`, same read |
| Domain separator | `0x71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818` | `DOMAIN_SEPARATOR()`, same read; `TestDomainSeparatorIsTheBaseSepoliaUSDCOne` recomputes it from the three values above |
| Decimals | 6 | `decimals()` |

Check them again before a deployment: `cast call <token> "name()(string)" --rpc-url <rpc>`, then `version()` and `DOMAIN_SEPARATOR()`. A wrong name or version makes every signature useless (the token recovers another address), and the zone refuses a domain that differs from its config.

## Configuration

Signing zone (`chains.<name>.evm`; the token also needs its `tokens` entry and an asset policy):

```json
"tokens": { "USDC": { "address": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "decimals": 6 } },
"x402":   { "USDC": { "name": "USDC", "version": "2", "max_window_seconds": 600, "per_payment_limit": "500000" } }
```

Business core (`chain`; same values, plus the hot shard that pays):

```json
"chain_id": 84532, "confirmations": 12,
"x402": { "USDC": { "name": "USDC", "version": "2", "max_window_seconds": 600, "per_payment_limit": "500000", "shard": 0 } }
```

The core and the zone must agree: a payload built from the core's values that differs from the zone's is refused (`tx_mismatch`). `per_payment_limit` is in the token's base units (500000 = 0.5 USDC).

**Pointing a dev deployment at the public Base Sepolia** is configuration only: `chain.rpc_url` to a Base Sepolia node (`https://sepolia.base.org` is rate limited; use a provider for anything steady), `chain_id` 84532, and the two blocks above. Nothing in CI does this: CI and every test use a local node (`make base-up` starts one; the tests also take any lane's anvil and set its chain id to 84532). Fund the hot address with test USDC from Circle's faucet, and test ETH is not needed for x402 (the facilitator pays the gas).

## The hot wallet

Give x402 its own hot shard (`shard`) with a small balance: an unused authorization can never take more than the wallet holds, and the open authorizations are shown as `x402_liability`. The refill tiers top it up like any other shard (limits per asset and shard in `cold.limits` and `cold.shard_limits`, `docs/tiers.md`). Keep the low-water mark above the largest `per_payment_limit` times the authorizations you expect open at once.

## Accounting

An authorization is a liability from the moment it is requested until the token shows it used or no block can include it:

| Step | Ledger | Table `x402_authorizations` |
|:---|:---|:---|
| Requested (`RequestX402`) | hold on `x402:<chain>:<asset>`, counter `hot:<partition>` | `requested`, then `signed` when the zone's job is done (`X402`) |
| Used: the token emitted `AuthorizationUsed(payer, nonce)` | hold posted: `x402` to `hot`, the amount that left the wallet | `used`, with the transaction and block |
| Expired: the final head's block time is at or past `validBefore` and no event was seen up to it | hold voided, nothing else booked | `expired` |
| Refused by the zone, or the job failed | hold voided | `refused`, with the zone's reason |

The worker learns of both endings by reading the token's `AuthorizationUsed` events for the hot address (`EVMReader.AuthorizationsUsed`, from the block before the request) in the pass `SettleX402` (every `scan.interval`), and the head's block time. The same event seen twice books once. A payment wins over an expiry seen in the same pass.

Reconcile adds a check `x402_liability` (the hold on the account equals the open rows) and explains the window in which the token has paid and the worker has not booked it yet, exactly as it does for a withdrawal that mined and is not settled: an event at or below the pinned height is put on the books' side of the hot check. A balance that fell without an `AuthorizationUsed` of ours, an expired authorization that was used after all, or a reader that cannot read events with authorizations open, is a difference and alerts.

## If it goes wrong

| Sign | Meaning | Action |
|:---|:---|:---|
| `wallet_not_gate_governed`, `credential_missing` or another credential code | The wallet is not in this checker's Gate setting, or the credential failed a check | [Gate setting](gate-setting.md), the job's reason and the `gate` field of the audit event |
| `tx_mismatch` on a new authorization | The core's and the zone's `x402` blocks differ, or the token's domain is not the configured one | Compare both configs with the token's `name()`, `version()` and `DOMAIN_SEPARATOR()` |
| `x402_liability` fails | The open rows and the holds differ, or the reader cannot read events | Look at `x402_authorizations` and `ledger_holds`; check the node's `eth_getLogs` range limit (the reader asks 2000 blocks at a time) |
| `hot` fails after a payment | Paid on chain, not booked, and not explained | Check the worker log for the x402 pass; an authorization released as expired and then used is a real loss of the books' view: find the transaction and book it by hand |
