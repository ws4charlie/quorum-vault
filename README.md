# QuorumVault

English | [中文](README.zh-CN.md)

A custody system for crypto: it holds customers' coins on EVM chains, Bitcoin and Solana, and moves them only when people with the right to approve have approved, and the system that holds the keys has checked it again on its own.

Exchanges and custodians lose money in two ways: a key gets stolen, or the books stop matching the chain. QuorumVault splits every key across several machines, so no single machine can sign, and it keeps a ledger that can be checked against the chain at any time.

Two rules carry the design:

- **The side that holds the keys trusts nothing it is told.** Every payment is read back and checked before any key signs.
- **The books must match the chain at every step.** A check called Reconcile compares them, down to the smallest unit.

## Architecture

<p align="center">
<a href="docs/identity.md"><img src="docs/images/arch-operators.png" width="24%" alt="Operators and approvers"></a><br/>
<picture><img src="docs/images/arch-a.png" width="24%" alt=""></picture><br/>
<a href="docs/identity.md"><img src="docs/images/arch-identity.png" width="24%" alt="Identity"></a><br/>
<picture><img src="docs/images/arch-b.png" width="24%" alt=""></picture><br/>
<picture><img src="docs/images/arch-api.png" width="24%" alt="Core API"></picture><br/>
<picture><img src="docs/images/arch-down.png" width="72%" alt=""></picture><br/>
<a href="docs/workflows.md"><img src="docs/images/arch-workflows.png" width="24%" alt="Workflows"></a><a href="docs/ledger.md"><img src="docs/images/arch-ledger.png" width="24%" alt="Ledger"></a><a href="docs/audit.md"><img src="docs/images/arch-audit.png" width="24%" alt="Audit trail"></a><br/>
<picture><img src="docs/images/arch-merge.png" width="72%" alt=""></picture><br/>
<a href="docs/tiers.md"><img src="docs/images/arch-tiers.png" width="24%" alt="Hot and cold"></a><br/>
<picture><img src="docs/images/arch-merge2.png" width="72%" alt=""></picture><br/>
<a href="docs/signing-zone.md"><img src="docs/images/arch-zone.png" width="48%" alt="Signing zone"></a><br/>
<picture><img src="docs/images/arch-down2.png" width="72%" alt=""></picture><br/>
<a href="docs/mpc.md"><img src="docs/images/arch-mpc.png" width="72%" alt="MPC parties"></a><br/>
<picture><img src="docs/images/arch-split.png" width="72%" alt=""></picture><br/>
<a href="docs/evm.md"><img src="docs/images/arch-evm.png" width="24%" alt="EVM"></a><a href="docs/bitcoin.md"><img src="docs/images/arch-bitcoin.png" width="24%" alt="Bitcoin"></a><a href="docs/solana.md"><img src="docs/images/arch-solana.png" width="24%" alt="Solana"></a>
</p>

## How it works

<p align="center"><img src="docs/images/flow.png" width="72%" alt="Deposits are credited, then swept to a hot wallet. Withdrawals need approvals and a signature. Above a limit the hot wallet sends coins to cold storage; below a limit it is refilled from cold."></p>

| Area | What it does |
|---|---|
| [Ledger](docs/ledger.md) | Records every coin in double entry and checks it against the chain |
| [Workflows](docs/workflows.md) | Carries each deposit, sweep and withdrawal through a crash |
| [Signing zone](docs/signing-zone.md) | Checks every payment before any key signs |
| [MPC signing](docs/mpc.md) | Splits each key across machines so no one machine can sign |
| [Hot and cold](docs/tiers.md) | Keeps a little online, the rest offline, and moves money between them |
| [EVM](docs/evm.md) · [Bitcoin](docs/bitcoin.md) · [Solana](docs/solana.md) | What is special about each chain |
| [Bitcoin sends](docs/bitcoin-sending.md) | How a Bitcoin send gets confirmed: fee room, replacement, cancel, child and batches |
| [Identity](docs/identity.md) | Who may call the API, and how a login is proved |
| [Audit trail](docs/audit.md) | A record of every decision that can't be quietly changed |
| [Testing](docs/testing.md) | How it is tested, including crashes and attacks |
| [Limits](docs/limits.md) | What it can't do yet |

## Try it

You need Go, Docker, SoftHSM and a C++ toolchain (clang, cmake, ninja).

```bash
make dev-env && make setup && make mpc-build
```

```bash
make test-e2e-all
```

The first command builds the MPC library once, which takes a few minutes. The second runs every test group CI runs, on local chains, in about ten minutes. Developer setup is in [CONTRIBUTING.md](CONTRIBUTING.md); runbooks are in [docs/runbooks](docs/runbooks) and measured numbers in [docs/measurements](docs/measurements).

## Status

| Verified | How |
|---|---|
| Deposits, sweeps, withdrawals, cold storage on EVM, Bitcoin and Solana | End-to-end tests on local chains, in CI |
| Crash safety | A worker is killed at every step of every flow; each payment settles once |
| Attacks on the signing side | A compromised gateway, party or database is refused |
| Login and approvals | A real OpenID Connect token is required; passkey approvals are checked by the signing zone. Tested with Keycloak and software authenticators, not hardware keys |
| Audit record | Chain heads are copied into write-once storage; tamper checks in tests |
| Real networks, real load | **Not yet.** No testnet or mainnet use, and no load test. See [Limits](docs/limits.md) |
