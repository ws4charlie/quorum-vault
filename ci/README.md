# CI image and helpers

The end-to-end jobs run their tests in one container image, `ghcr.io/ws4charlie/qv-ci:<hash>`, instead of installing the C++ toolchain, SoftHSM and
Go and building cb-mpc in every job.

| File | What it does |
|---|---|
| `qv-ci.Dockerfile` | The image: clang-20 (via `mpc-party/scripts/install-toolchain-linux.sh`), cb-mpc at `mpc-party/cbmpc.pin` (via `mpc-party/scripts/fetch-build-cbmpc.sh`), SoftHSM2, Go, the docker CLI. Tools and libraries only. |
| `image-tag.sh` | The tag: a hash of the Dockerfile, its two scripts, the pin and go.mod's Go version. An image can never be stale. |
| `ensure-image.sh` | `publish` (the `image` job): build and push when the tag is missing. `use` (every other job): pull it, or build it locally from the same Dockerfile. |
| `run-in-image.sh` | Runs a command in the image, in the checkout, on the host network, with the Docker socket. `ci/run-in-image.sh make test-e2e-btc-recovery` |
| `solana/Dockerfile` | The local Solana validator (Agave, pinned by version and checksum) for the Solana tests. Built once per change of this file by the `image` job (`ensure-image.sh publish solana`, tag from `image-tag.sh solana`, `ghcr.io/ws4charlie/qv-solana:<hash>`); the Solana job pulls it. On a laptop compose builds it. |
| `infra.sh` | Starts anvil, Temporal, Redpanda, bitcoind and the Solana validator in the background (`start`) and waits for them right before the tests (`wait`). |

**No secrets in the image.** The SoftHSM tokens are created at job time by `scripts/setup-softhsm.sh`, in the checkout; the PINs are generated
at job time by `scripts/dev-env.sh` into the checkout's `.env`. The image is public like the repository.

**Same-repository pull requests and pushes** push a new tag from the `image` job (`packages: write` on that job only). **Fork pull requests** cannot
push: their jobs pull the tag if `main` has it, and otherwise build the image themselves from the same Dockerfile (a few minutes, once per job).

**After the first push** the package `qv-ci` is private until an owner of the repository makes it public (GitHub > Packages > qv-ci > Package
settings > Change visibility). Jobs of this repository pull it with their own token either way; fork pull requests need it public.

Run it locally (Linux or macOS with Docker; the image is built for your machine's architecture):

```bash
ci/ensure-image.sh use
ci/run-in-image.sh go vet ./...
```
