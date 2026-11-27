# CI image and helpers

The end-to-end jobs run their tests in one container image, `ghcr.io/ws4charlie/qv-ci:<hash>`, instead of installing the C++ toolchain, SoftHSM and
Go and building cb-mpc in every job.

| File | What it does |
|---|---|
| `qv-ci.Dockerfile` | The image: clang-20 (via `mpc-party/scripts/install-toolchain-linux.sh`), cb-mpc at `mpc-party/cbmpc.pin` (via `mpc-party/scripts/fetch-build-cbmpc.sh`), SoftHSM2, Go, the docker CLI. Tools and libraries only. |
| `image-tag.sh` | The tag: a hash of the Dockerfile, its two scripts, the pin and go.mod's Go version. An image can never be stale. |
| `ensure-image.sh` | `publish` (the `changes` job, first): build and push when the tag is missing. `use` (every other job): pull it, or build it locally from the same Dockerfile. |
| `run-in-image.sh` | Runs a command in the image, in the checkout, on the host network, with the Docker socket. `ci/run-in-image.sh make test-e2e-btc-recovery` |
| `solana/Dockerfile` | The local Solana validator (Agave, pinned by version and checksum) for the Solana tests. Built once per change of this file by the `changes` job (`ensure-image.sh publish solana`, tag from `image-tag.sh solana`, `ghcr.io/ws4charlie/qv-solana:<hash>`); the Solana job pulls it. On a laptop compose builds it. |
| `promtool-tests.sh` | In the `checks` job: `promtool check rules`, `check config` and the rule unit tests of `monitoring/`, then the Go tests that use promtool (`monitoring/`, the failure-counter alert in `mpc-party/internal/server`). A skipped test or a missing promtool fails it. promtool v3.5.0 (the version `docker-compose.yml` pins) is in the image, checked by SHA-256. |
| `infra.sh` | Starts anvil, Temporal, Redpanda, bitcoind and the Solana validator in the background (`start`) and waits for them right before the tests (`wait`). |

**No secrets in the image.** The SoftHSM tokens are created at job time by `scripts/setup-softhsm.sh`, in the checkout; the PINs are generated
at job time by `scripts/dev-env.sh` into the checkout's `.env`. The image is public like the repository.

**Same-repository pull requests and pushes** push a new tag from the `changes` job (`packages: write` on that job only). **Fork pull requests** cannot
push: their jobs pull the tag if `main` has it, and otherwise build the image themselves from the same Dockerfile (a few minutes, once per job).

**After the first push** the package `qv-ci` is private until an owner of the repository makes it public (GitHub > Packages > qv-ci > Package
settings > Change visibility). Jobs of this repository pull it with their own token either way; fork pull requests need it public.

Run it locally (Linux or macOS with Docker; the image is built for your machine's architecture):

```bash
ci/ensure-image.sh use
ci/run-in-image.sh go vet ./...
```

## Which jobs run on a pull request

The human's rule: never skip a job a change can affect; running too much is fine, missing a run is not. The `changes` job decides, and every doubt,
error or unknown path runs every job.

1. Every changed file on `skip-allowlist` (documentation, three charts, `ci/helm`): every heavy job is skipped (`classify.sh`, `skip-guard.sh`).
2. Otherwise `jobselect` (Go, standard library only) works out, file by file, the jobs a change can affect, and the others are skipped:

| Changed file | Jobs |
|---|---|
| a `.go` file of a package | the jobs that compile the package (`go list` of every module, under every build tag CI uses: the packages a job tests, their test imports, every binary an e2e test builds, and all they import); a `_test.go` file: only the jobs that test its package |
| a file under a tree of `job-rules` (`ci/kind`, `deploy/helm`, `loadtest`, `monitoring`) | the jobs that read the tree: its Go packages, every Go file elsewhere that names it, the ci.yml job or Makefile target that names it, and the reviewed lines of `job-rules-exceptions` |
| anything else (`go.mod`, `.github/`, the rest of `ci/`, scripts, compose, migrations, a new directory, a mode change, a rename) | every job |

| File | What it is |
|---|---|
| `jobs` | each job of ci.yml and the Go packages it tests (`job <id> <module>:<pattern>... [@mains]`); `test` is `always` (root tests read other modules' files) |
| `job-rules`, `job-rules-exceptions` | the non-Go trees whose readers are found by a search, and the reviewed readers the search cannot map to jobs |
| `job-readers` | every Go file that reads by a path relative to `..` or the repository root, with the paths it reads (a change there adds its jobs) |
| `jobselect/` | the selector: `select` (the decision), `explain <path>` (why), `readers` (the evidence for each tree), `why <job> <dir>` (the import chain), `check` (the guard) |

`jobselect check` runs in the `changes` job and fails when ci.yml and `jobs` disagree: a job missing from either, a job whose condition does not name its
own id, an e2e job that does not need `build`, a Go file reading by a relative path that is not in `job-readers`, a reader of a tree that is not reviewed, a build tag that is not modelled, an mpc-party file that reaches
into the root module. A new job therefore goes into `jobs` with the packages it tests, and gets the condition

```yaml
    needs: [changes, build]
    if: ${{ !cancelled() && needs.build.result == 'success' && !(needs.changes.result == 'success' && contains(needs.changes.outputs.skip_jobs, ',<id>,')) }}
```

```bash
go run ./ci/jobselect explain internal/custody/service.go loadtest/scenarios/smoke.json
```

A commit message with `[ci full]` runs everything.

## Build once, 20 jobs

The free plan runs 20 jobs at once, so ci.yml has 20: `changes` (the decision, its guards, and the CI image), `build`, `test`, three mpc-party jobs,
`checks`, and 13 end-to-end jobs of about seven to nine minutes of tests each, by chain. `build` compiles once what every e2e job used to compile for
itself: the binaries the harnesses start and the e2e test binaries (`e2e-prebuild.sh`); the e2e jobs download them.

| File | What it does |
|---|---|
| `e2e-prebuild.sh` | the `build` job: the harness binaries (named by `e2e/mpcstack.PrebuiltKey`), and a test binary for every package a make target in ci.yml tests, with a manifest |
| `gotest.sh` | `go test` for the e2e make targets in CI (`QV_GOTEST`): runs the prebuilt test binary in the package directory with the same flags; anything it does not model runs `go test` |
| `run-groups.sh` | runs a job's groups one after another, each with its own time limit and environment, all of them even when one fails, and prints a summary |
| `e2e-groups-check.sh` | every e2e group of the Makefile runs in some job; `--list-ci` lists every test CI runs through make |

In the e2e jobs `QV_E2E_PREBUILT_STRICT=1`: a harness that asks for a binary `e2e-prebuild.sh` does not make fails, instead of compiling it in every job.

## The Go build cache

`build` restores `~/.cache/qv-go` (modules and build cache, mounted into the image) keyed on `go.sum` and the commit, and saves it on pushes to `main`
only, so a pull request starts from the newest `main` build. The e2e jobs restore the same cache (a few tests still build a binary at run time), the
mpc-party jobs and `checks` their own (`go-cache` and `go-cache-save` of `.github/actions/mpc-env`), and `test` its own. Pull requests never save:
their caches would push `main`'s out of the repository's 10 GB.
