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

`make dev-env` writes `.env` (gitignored) with random SoftHSM PINs and never overwrites an existing one. `make setup` creates the SoftHSM tokens, the certificates (below), the Postgres servers (business on 55432, the signing zone's replay guards on 55433) and an anvil node.

## Tests

| Command | What it runs |
|---|---|
| `make test-short` | Unit and integration tests, fast |
| `make test` | Every package; fails instead of skipping if Postgres or SoftHSM is missing |
| `make test-e2e-all` | Every CI group at once, in parallel lanes, about ten minutes with 8 lanes. Needs Docker, `make softhsm mpc-build` once, and leaves the ports of `make setup` alone |
| `make test-e2e-all GROUPS=e2e-btc-cold,test` | Some groups (`evm`, `btc` and `sol` stand for all of theirs); `LANES=4` changes the lane count. It needs about 5.5 GB of free memory in the Docker VM (a Solana validator is ~1.6 GB) and refuses to start with a message when there is less; `QV_E2E_FORCE=1` overrides |

**Several worktrees on one machine.** Every local e2e run takes its compose project name (`qve2e-<hash of the checkout path>`) and its block of 100 host ports (from 12000) from the checkout it runs in, so two worktrees can run any groups at the same time; in CI the fixed names and ports stay. `make e2e-lane` prints them, and a variable set in the environment wins. `make test-e2e-all` waits for a free slot when the lanes already running on the machine reach `QV_E2E_MAX_LANES` (default from CPUs and memory) and prints who holds them (`make e2e-slots`); it removes its containers on failure and on Ctrl-C. `make e2e-clean` removes the stacks of this checkout only (also the ones started by `make db-up`, `infra-up` and the like), and `make e2e-clean-stale` lists, then removes, the stacks of worktrees that no longer exist.

`make images` builds the container image of every service and the two tools images (`deploy/images/`, run-time contract in its README); `deploy/images/smoke.sh` and `deploy/images/check-secrets.sh` check them. Nothing is pushed.

Each group writes a log under `data/e2e-all/`. Pull requests run the light groups; the heavy crash and failure groups run nightly or from the Actions tab. `QV_CRASH_BOUNDARIES` picks crash points, and `make test-e2e-evm TEST=<name>` runs a single test. The `mpc-party` module has its own tests (`cd mpc-party && go test ./...`).

`make db-up` also applies the migrations as the owner role (`make migrate` does it alone): `qv-core` and `qv-worker` only check that they are applied and refuse to start otherwise. See [docs/runbooks/database-roles.md](docs/runbooks/database-roles.md).

## Logging in to the core API

The core API wants a bearer token. For development, start Keycloak with `make keycloak-up` (the realm in `deploy/keycloak` has the test users alice, bob, carol and ops; their random passwords, the admin console's and the guardian client's secret are written to `.env` as `QV_TEST_PASSWORD_<NAME>`, `QV_KEYCLOAK_ADMIN_PASSWORD` and `QV_KEYCLOAK_GUARDIAN_SECRET`; nothing is in the repo), then start `qv-core` with `QV_ENV=dev QV_OIDC_ISSUER=http://127.0.0.1:8180/realms/quorumvault QV_OIDC_AUDIENCE=qv-core`. A token for a script comes from `curl -s -d grant_type=client_credentials -d client_id=qv-guardian -d client_secret=$QV_KEYCLOAK_GUARDIAN_SECRET http://127.0.0.1:8180/realms/quorumvault/protocol/openid-connect/token`. People log in with the `qv-cli` client (authorization code with PKCE, then a passkey). Without Keycloak, `QV_ENV=dev QV_DEV_ACTOR_HEADER=1` brings back the old `X-Actor` header; a production start refuses it. See [docs/identity.md](docs/identity.md).

## Certificates

Services and both Postgres servers talk over TLS with client certificates only (no passwords). `make setup` runs `scripts/pki.sh`, which makes one private CA per trust zone (business, signing) and a short-lived certificate for every service under `data/pki` (gitignored; nothing is committed). Run `make pki` again to rotate: running services reload the new files, no restart. `make test-e2e-all` and every CI job make fresh ones, and tests without `QV_PKI_DIR` make their own. Plain http is only for a dev machine that sets `QV_ALLOW_PLAINTEXT=1` with `QV_ENV=dev`; production refuses it. What a deployment must provide is in [docs/runbooks/certificates.md](docs/runbooks/certificates.md).

## Configuration

All optional; see [.env.example](.env.example). `DATABASE_URL`, `SOFTHSM2_CONF`, `QV_HSM_PIN` (the gateway reads `QV_HSM_PIN_FILE` outside dev and test: [docs/runbooks/hsm-pin.md](docs/runbooks/hsm-pin.md)), `QV_PKCS11_LIB` and `QV_CUSTODY_SIGNER` (`hsm` or `mpc`) are the ones you meet first.

## More

- [docs/runbooks](docs/runbooks): MPC backup and restore, keyset freeze, cold refill, stolen hot key
- [docs/measurements](docs/measurements): the numbers, with how they were measured
- [docs/spikes](docs/spikes): decision records
- [mpc-party/README.md](mpc-party/README.md): the MPC wrapper and service
- [DESIGN_SCALE.md](DESIGN_SCALE.md): what scaling would need
