# Contributing

The concepts are in the [README](README.md) and [docs](docs). This file is the developer setup.

> **Local chains only.** Everything runs against local nodes. Test PINs are generated on your machine, and nothing here holds a real key. Never point this code at real funds.

## Prerequisites

Go with CGO, Docker, SoftHSM2 and, for the MPC parts, a C++ toolchain (clang, cmake, ninja). `make mpc-build` fetches and builds cb-mpc at the pinned commit into `mpc-party/.deps`; the first run takes a few minutes.

```bash
brew install softhsm           # Ubuntu: apt-get install softhsm2
```

```bash
make dev-env && make setup && make mpc-build
```

`make dev-env` writes `.env` (gitignored) with random SoftHSM PINs and never overwrites an existing one. `make setup` creates the SoftHSM tokens, Postgres on port 55432 and an anvil node.

## Tests

| Command | What it runs |
|---|---|
| `make test-short` | Unit and integration tests, fast |
| `make test` | Every package; fails instead of skipping if Postgres or SoftHSM is missing |
| `make test-e2e-all` | Every CI group at once, in parallel lanes, about ten minutes. Needs Docker, `make softhsm mpc-build` once, and leaves the ports of `make setup` alone |
| `make test-e2e-all GROUPS=e2e-btc-cold,test` | Some groups (`evm`, `btc` and `sol` stand for all of theirs); `LANES=4` changes the lane count. It needs about 5.5 GB of free memory in the Docker VM (a Solana validator is ~1.6 GB) and refuses to start with a message when there is less; `QV_E2E_FORCE=1` overrides |

Each group writes a log under `data/e2e-all/`. Pull requests run the light groups; the heavy crash and failure groups run nightly or from the Actions tab. `QV_CRASH_BOUNDARIES` picks crash points, and `make test-e2e-evm TEST=<name>` runs a single test. The `mpc-party` module has its own tests (`cd mpc-party && go test ./...`).

## Configuration

All optional; see [.env.example](.env.example). `DATABASE_URL`, `SOFTHSM2_CONF`, `QV_HSM_PIN`, `QV_PKCS11_LIB` and `QV_CUSTODY_SIGNER` (`hsm` or `mpc`) are the ones you meet first.

## More

- [docs/runbooks](docs/runbooks): MPC backup and restore, keyset freeze, cold refill, stolen hot key
- [docs/measurements](docs/measurements): the numbers, with how they were measured
- [docs/spikes](docs/spikes): decision records
- [mpc-party/README.md](mpc-party/README.md): the MPC wrapper and service
- [DESIGN_SCALE.md](DESIGN_SCALE.md): what scaling would need
