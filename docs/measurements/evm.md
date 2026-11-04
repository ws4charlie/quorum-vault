# EVM cell measurements (P2)

Local anvil (Foundry v1.8.5, chain ID 11155111, cancun), solc 0.8.26, optimizer 200 runs. Machine: Apple M3 Pro, local Postgres 16 in Docker. These numbers are for local sanity and relative cost only: block production is instant here, RPC latency is ~0, and real-network scan and gas prices differ.

Reproduce: `forge test -vv` in `contracts/` (via the Foundry image, see `contracts/build.sh`) and
`QV_EVM_RPC_URL=http://127.0.0.1:18545 go test -v -count=1 -p 1 -run 'EndToEnd|PlainSend|Measure' ./internal/chain/evm`.

## Gas (final design: persistent forwarder, destination in the factory)

P3b added `event Swept(address indexed token, uint256 amount)` to each flush that moves funds (accounting reads what actually moved). It costs about 1.4-1.9k gas per event; the numbers below include it (before: 369,221 / 58,973 / 44,444 / 36,448 / 2,916,085 / 280,760 by forge, 359,369 / 44,199 on anvil).

| Operation | Gas | Source |
|---|---:|---|
| `deployAndFlush`: deploy forwarder + flush ETH + 1 token | 396,274 | forge --isolate |
| same, mined on anvil (ETH + 1 token) | 386,387 | Go e2e |
| `deployAndFlush` on a deployed forwarder (ETH + 1 token) | 61,953 | forge |
| same, mined on anvil (1 token, no ETH) | 45,710 | Go e2e |
| `flushTokens(token)` direct | 45,906 | forge |
| `flushETH()` direct | 37,882 | forge |
| `deployAndFlushMany`, 10 addresses, first (ETH + 1 token each) | 3,186,202 | forge |
| `deployAndFlushMany`, 10 addresses, repeat | 310,228 | forge |

Rough cost of a first sweep at 30 gwei: 396k x 30 gwei = 0.012 ETH; later sweeps about 62k x 30 gwei = 0.0019 ETH. The sweep rule `value >= k x fee` (PLAN, k 20-50) uses `EstimateSweepFee`.

## Depositing to a forwarder (gas a sender needs)

`receive()` is empty: it accepts ETH and forwards nothing, so a deposit looks the same before and after deployment; the sweep moves it.

| Case | Result |
|---|---|
| Before deployment (empty account), plain send, limit 21,000 | succeeds |
| After deployment, limit exactly 21,000 | **reverts**, value stays with the sender (the code must still run) |
| After deployment, smallest limit that succeeds (real transactions, binary search) | **21,055** (`eth_estimateGas` also 21,055) |
| Contract using Solidity `transfer()` (2,300 gas to the receiver) | succeeds |

So wallets and exchanges that hard-code 21,000 fail after deployment, but any estimate (or a limit a little above 21,000) works. A reverted send is not a deposit: Scan ignores it.

## Rejected design: one-shot sweeper (spike, removed)

A contract whose constructor sweeps and `SELFDESTRUCT`s (EIP-6780 deletes it in its creating transaction) leaves no code, so 21,000-gas sends work and the destination can change without moving addresses. Measured on real anvil transactions (Cancun and the latest hardfork): it worked, with a first sweep of about 91k gas (vs 332k then) but about 91k for every repeat (vs 48k). Rejected for depending on a deprecated opcode: if a fork stops deleting the account the address becomes permanently unsweepable with no recovery path. The final design gets the changeable destination from the factory instead.

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
