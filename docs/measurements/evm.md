# EVM cell measurements (P2)

Local anvil (Foundry v1.8.5, chain ID 11155111, cancun), solc 0.8.26, optimizer 200 runs. Machine: Apple M3 Pro, local Postgres 16 in Docker. These numbers are for local sanity and relative cost only: block production is instant here, RPC latency is ~0, and real-network scan and gas prices differ.

Reproduce: `forge test -vv` in `contracts/` (via the Foundry image, see `contracts/build.sh`) and
`QV_EVM_RPC_URL=http://127.0.0.1:18545 go test -v -count=1 -p 1 -run 'EndToEnd|PlainSend|Measure' ./internal/chain/evm`.

## Gas

| Operation | Gas | Source |
|---|---:|---|
| `deployAndFlush`: deploy forwarder + flush ETH + 1 token | 334,105 | forge |
| same, as mined on anvil (sweep tx, 1 token, ETH deposit) | 324,267 | Go e2e |
| `deployAndFlush` on a deployed forwarder (ETH + 1 token) | 55,466 | forge |
| same, as mined on anvil (1 token, no ETH) | 40,694 | Go e2e |
| `flushTokens(token)` called directly | 38,924 | forge |
| `flushETH()` called directly | 31,081 | forge |

Rough cost of the first sweep at 30 gwei: 334k x 30 gwei = 0.010 ETH; later sweeps 55k x 30 gwei = 0.0017 ETH. The sweep rule `value >= k x fee` (PLAN, k 20-50) uses `EstimateSweepFee`.

## Known limit: plain ETH send to a deployed forwarder

A transaction with the standard 21,000 gas limit to a deployed forwarder **reverts**: after the 21,000 intrinsic gas nothing is left for `receive()`, which makes a CALL to the destination.

| Measure | Gas |
|---|---:|
| Plain send, limit 21,000 | reverts (status 0, no value moves) |
| Gas the sender must supply to a deployed forwarder (`eth_estimateGas`, anvil) | 57,760 |
| Gas actually used by that send | 55,544 |
| Minimum gas forwarded to `receive()` itself (forge, call with explicit gas) | 9,460 |

A sender needs a gas limit of **about 60,000** (estimate + margin). Wallets that estimate gas get this right; wallets and exchanges that hard-code 21,000 for "plain" sends will fail, and the failed transaction is not a deposit: Scan ignores reverted transactions. Before the first sweep (forwarder not yet deployed) the address is an empty account and 21,000 gas works. ETH sent with 21,000 gas before deployment is swept by `deployAndFlush`.

## Scan speed

`Scan` over 2,000 empty blocks plus 2 deposits (1 native, 1 ERC-20), 8 block-fetch workers, one `eth_getLogs` per 2,000 blocks:

| Blocks | Deposits | Time | Rate |
|---:|---:|---:|---:|
| 2,000 | 2 | 0.56-0.58 s | ~3,500 blocks/s |

The native scan fetches every block with transactions (cost grows with block size and RPC latency); the ERC-20 scan is one log query per 2,000 blocks and 200 deposit addresses. With real RPC latency (tens of ms) expect two orders of magnitude lower; a production indexer should keep its own cursor (`SafeHeadHeight`) and only scan new blocks.

## Nonce allocation

`allocateNonce` (lock `evm_nonces` row, find-or-insert allocation, advance counter), local Postgres, excluding the RPC calls for fees and gas:

| Pattern | Allocations | Rate |
|---|---:|---:|
| 200 in one transaction | 200 | ~600-680 /s |
| 200, one transaction each | 200 | ~640-680 /s |

One writer per address caps a single hot address at roughly this rate, far above what a chain accepts from one sender (nodes limit queued transactions per sender). More throughput comes from sharding hot wallets (PLAN: K child addresses), not from the nonce manager.
