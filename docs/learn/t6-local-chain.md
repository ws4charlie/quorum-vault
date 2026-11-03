# T6 — A local chain that pretends to be Sepolia

Until T6 every signed transaction was only checked on this machine: decode
it, recover the sender, compare with the wallet address. Nothing had ever
been sent to a node. T6 runs a local Ethereum node (anvil) that reports
Sepolia's chain ID, so the exact bytes the sign path produces are broadcast,
mined and checked by receipt — in a Go test suite and in CI on every push.

## What was built

| Piece | Where | Job |
|---|---|---|
| anvil service | [docker-compose.yml](../../docker-compose.yml) | `anvil --host 0.0.0.0 --chain-id 11155111` on 127.0.0.1:8545, pinned image `ghcr.io/foundry-rs/foundry:v1.8.5` |
| Make targets | [Makefile](../../Makefile) | `chain-up`, `chain-down`, `test-e2e`; `setup` now also starts anvil |
| Safety check + funding | [e2e/localchain.go](../../e2e/localchain.go) | `CheckLocalChain` (host, client name, chain ID), `SetBalance` (`anvil_setBalance`) |
| e2e tests | [e2e/e2e_test.go](../../e2e/e2e_test.go) | the real service over HTTP, broadcast on, receipts and balances checked |
| Refusal tests | [e2e/localchain_test.go](../../e2e/localchain_test.go) | fake JSON-RPC nodes that must be refused |
| Receipt wait | [internal/chain/eth/eth.go](../../internal/chain/eth/eth.go) `WaitReceipt` | poll `eth_getTransactionReceipt` until mined or the context ends |
| Nonce fix | [internal/signing/service.go](../../internal/signing/service.go) `freshNonce` | re-check the nonce against the node at sign time |
| CI job `e2e` | [.github/workflows/ci.yml](../../.github/workflows/ci.yml) | Postgres service + `docker run` anvil + `go test ./e2e/...` |
| Demo local mode | [scripts/demo-sepolia.sh](../../scripts/demo-sepolia.sh) `--local` | funds wallets, prints receipts; output in [docs/measurements/e2e.md](../measurements/e2e.md) |

## anvil vs geth --dev vs a real testnet

| | anvil | geth `--dev` | Sepolia |
|---|---|---|---|
| What it is | Foundry's in-memory dev node (Rust) | the real client in single-node dev mode | public testnet, real validators |
| Chain ID | anything (`--chain-id`) | 1337 by default (configurable via genesis) | 11155111, fixed |
| Blocks | automine: one block per tx, inside the send call | periodic or on demand | one slot every 12 s |
| Funding | `anvil_setBalance`, 10 prefunded dev accounts | one prefunded dev account, transfer from it | faucets (rate-limited, slow) |
| State | gone on restart | optional datadir | permanent, public |
| Use here | tests and CI: fast, deterministic, free | not used | optional manual run |

ZetaChain's localnet uses both (`eth` = geth --dev, `eth2` = anvil with
`--chain-id 11155111`). We need only one, and anvil's cheat methods
(`anvil_setBalance`) make funding a single call with no private key.

## Why chain ID 11155111 makes our txs valid on the local node

An EIP-1559 transaction (type 2) carries its chain ID **inside the signed
payload**:

```
digest = keccak256(0x02 || rlp([chainId, nonce, tip, feeCap, gas, to, value, data, accessList]))
```

So the signature commits to chain 11155111 ([eth.go](../../internal/chain/eth/eth.go)
`BuildTx` / `Digest`). This is EIP-155 replay protection carried into typed
transactions: a node rejects a tx whose chain ID differs from its own, and a
tx signed for Sepolia can never be replayed on mainnet (chain 1). The other
side of the coin: a node that *claims* 11155111 accepts our Sepolia txs
unchanged. anvil's default is 31337; started with `--chain-id 11155111` it
validates our bytes exactly as Sepolia would (signature, chain ID, nonce,
balance, fee cap ≥ base fee) and mines them. Nothing in the sign path
changes for the test.

## Funding with `anvil_setBalance`

```json
{"method":"anvil_setBalance","params":["0x<wallet address>","0x8ac7230489e80000"]}
```

writes 10 ETH straight into the account state. No transfer, no funded
account, no private key — which is why the repo does not need (and must not
contain) anvil's well-known dev keys. `SetBalance` in
[localchain.go](../../e2e/localchain.go) and `fund` in the demo do this right
after a wallet is created.

## Receipts and effective gas price

A receipt is the node's record of a mined tx: `status` (1 ok, 0 reverted),
`blockNumber`, `gasUsed`, `effectiveGasPrice`, `from`, `to`. The tests check:

- `status == 1` and the node's own `from` (from `eth_getTransactionByHash`)
  is the wallet address — the node recovered the same sender we did;
- recipient balance at the tx's block minus the block before == value;
- sender balance went down by exactly `value + gasUsed × effectiveGasPrice`.

`effectiveGasPrice = min(maxFeePerGas, baseFee + maxPriorityFeePerGas)`. The
server signs `maxFeePerGas = 2 × baseFee + tip` (see `Suggest`), so the cap is
never hit and the price paid is base fee + 1 gwei tip. The base fee is burned,
the tip goes to the block producer; the sender pays both. A plain transfer to
an account with no code uses exactly 21000 gas.

## Why the tests refuse non-local endpoints

`SEPOLIA_RPC_URL` is also the switch for a real Sepolia node. A developer may
have a real URL in `.env`, and `make test` loads `.env`. If the e2e tests ran
against it they would sign and broadcast real (testnet) transactions from
test wallets, and `anvil_setBalance` would fail in confusing ways. So
`CheckLocalChain` refuses, in this order:

1. scheme not plain `http`/`ws` (a dev node never needs TLS);
2. host not `localhost`, `127.0.0.1`, `::1` or `anvil` (compose service
   name) — checked **before** any request is sent;
3. `web3_clientVersion` without `anvil` (geth, Nethermind, a provider);
4. `eth_chainId` not 11155111 (anvil with its default 31337, or mainnet).

Any of these is `t.Fatal`, not a skip. The four refusal tests in
[localchain_test.go](../../e2e/localchain_test.go) run without a node (fake
JSON-RPC servers on 127.0.0.1) and even under `-short`. The demo's
`check_local_chain` applies the same rules in bash.

## The bug the chain found

T4 filled the nonce at **Submit** time from the node (`PendingNonceAt`). A
request that waits for approval keeps that nonce. If a later small transfer
of the same wallet is allowed and broadcast first, it takes the same nonce;
when the first request is finally approved its tx is refused with
`nonce too low` — the request ends `signed` but never lands.

The fix (`sign` → `freshNonce` in [service.go](../../internal/signing/service.go)):
with broadcast on, the service takes a per-sender lock, asks the node for the
pending nonce, and moves the request's nonce **up** to it when it is lower.
A nonce at or above the pending one is kept (the caller chose it). The lock
is held until the broadcast returns so two requests of one wallet never take
the same nonce. The signed nonce is stored on the request, and `sign.started`
records `nonce` and `nonce_reassigned_from`. Regression test:
`TestLocalChain/ApprovedAfterLaterTransferGetsFreshNonce` (it fails with
`nonce too low` without the fix). Limits: the lock is in-process (one server
instance); a multi-instance service needs a shared nonce manager.

## Gotchas

- The foundry image's entrypoint is `/bin/sh -c`, so the compose `command`
  is one string: `"anvil --host 0.0.0.0 --chain-id 11155111"`.
- `--host 0.0.0.0` is needed inside the container; the port is published on
  `127.0.0.1` only, so nothing outside this machine can reach it.
- GitHub service containers cannot take a command, so CI starts anvil with
  `docker run` and polls `eth_chainId` until it answers.
- The receipt appears a few ms after `eth_sendRawTransaction` returns; poll,
  never assume it is there.
- MPC pre-params are sealed under the party tokens; CI makes fresh tokens
  each run, so the first MPC wallet there pays the full pre-params cost.
- Packages still run with `-p 1` (shared SoftHSM token files).

## Quiz

1. Why does a tx signed for chain ID 11155111 get mined by anvil, and what
   flag makes that true?
2. Where exactly is the chain ID in an EIP-1559 tx, and what attack does
   that stop?
3. What does `anvil_setBalance` do that a transfer would not, and why does
   that keep private keys out of the repo?
4. Name the four checks `CheckLocalChain` makes, and why the host check runs
   before any request.
5. A receipt shows `gasUsed = 21000`, `effectiveGasPrice = 1.09 gwei`, value
   0.003 ETH. How much did the sender's balance drop?
6. Why is `effectiveGasPrice` lower than the signed `maxFeePerGas` here?
7. Describe the nonce bug: which order of requests triggered it, and what
   error did the node return?
8. Why does the fix move the nonce only **up**, and why hold a lock until the
   broadcast returns?
9. Why is the safety refusal `t.Fatal` instead of `t.Skip`?
10. Why does CI use `docker run` for anvil instead of a `services:` entry?

<details>
<summary>Answers</summary>

1. The signature commits to the chain ID, and a node accepts a tx only if it
   matches its own. `anvil --chain-id 11155111` makes anvil report and
   enforce Sepolia's ID, so our bytes are valid there unchanged.
2. It is the first field of the RLP list hashed into the signing digest
   (`0x02 || rlp([chainId, ...])`). It stops cross-chain replay (EIP-155):
   a Sepolia tx cannot be replayed on mainnet or any other chain.
3. It writes the balance directly into state; no funded sender, so no
   signing key is needed. The 10 prefunded dev accounts' keys are public but
   still never belong in a repo.
4. Scheme plain http/ws; host localhost/127.0.0.1/::1/anvil;
   `web3_clientVersion` contains `anvil`; `eth_chainId` == 11155111. The host
   check runs first so a real endpoint never even receives a request.
5. 0.003 ETH + 21000 × 1.09 gwei = 0.003 ETH + 22,890 gwei
   (0.00002289 ETH) = 0.00302289 ETH.
6. effective = min(feeCap, baseFee + tip); feeCap = 2 × baseFee + tip, so
   baseFee + tip is always the smaller one.
7. A request needing approval got nonce N at Submit; a later allowed transfer
   also got N and was mined first; the approved one then failed with
   `nonce too low`.
8. Lower than pending is guaranteed to be refused; equal or higher may be
   the caller's intent, so it is kept. The lock stops two concurrent signs of
   one wallet from both reading pending N before either broadcasts.
9. A refusal means SEPOLIA_RPC_URL points somewhere real or wrong; skipping
   would hide that, failing makes it visible and still sends nothing.
10. Service containers run the image's default command only; anvil needs
    `--chain-id 11155111` and `--host 0.0.0.0` as arguments.

</details>
