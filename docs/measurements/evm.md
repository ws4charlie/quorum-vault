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

## Fix round 1: A (forwarder) vs B (one-shot sweeper), ETH + 1 USDT-style token

A = `Forwarder` + `ForwarderFactory.deployAndFlush`; B = `SweepFactory` + `OneShot` (spike, `contracts/src/SweepFactory.sol`, not wired into the adapter). Foundry `--isolate` (each call is its own transaction), gas measured around the call (the 21,000 base is not included).

| Case | A | B |
|---|---:|---:|
| First sweep, one address | 332,040 | 90,909 |
| Repeat sweep, one address | 48,470 | 90,909 |
| 10 addresses, first sweep | 2,877,419 (10 calls) | 546,882 (one `sweepMany`) |
| 10 addresses, repeat sweep | 462,691 (10 calls) | 546,884 (one `sweepMany`) |

Mined on anvil (gas used by the whole transaction, including the 21,000 base): B first sweep 122,925, repeat 80,825, batch of 10 in one transaction 492,650; with two tokens 153,757 / 94,557. A on anvil (round 1 report): 324,267 first, 40,694 repeat (token only).

B pays the same every time (no state to keep: no CREATE2 deployment beyond the one-shot's tiny init code, no storage). A is cheaper only after its first sweep, by about 2x.

### B on real transactions
`go test -run Spike` against anvil with `--hardfork cancun` and with the latest hardfork anvil v1.8.5 offers (reported as `Amsterdam`), all passing on both:
- 4 rounds of deposit, sweep, deposit on one address: all funds reach the destination every time; `eth_getCode` is empty after every sweep; every deposit is a plain send with a **21,000 gas limit** and succeeds; an additional 1 wei dust deposit swept with no token list also moves.
- ETH only, token only (USDT-style, no return value), both, and an empty sweep.
- `setDestination` by a non-admin reverts; after an admin change the existing deposit address (unchanged) sweeps to the new destination.
- The same salt twice in one transaction (`sweepMany([s, s])`) reverts as `DuplicateSalt` (129k gas used, nothing moves, no code). Without the check, the second CREATE2 collides with the first one-shot, which is still alive until the transaction ends, and burns all forwarded gas. A token whose `transfer` reverts reverts the whole sweep (ETH too); funds stay, and sweeping again without that token recovers the rest.

### Foundry `--isolate` quirk
In `forge test --isolate`, after "sweep, 1 wei stipend send, tokenless sweep", the second sweep zeroed the address balance without crediting the destination (1 wei vanished; with a later 2 ETH deposit, those 2 ETH vanished too). The identical sequence on anvil, on both hardforks, moves every wei. I could not explain it; treat it as a Foundry state-caching artifact, but it is a reason not to rely on Foundry alone for B. `testStipendSendAfterSweep` stops before that point and says so.
