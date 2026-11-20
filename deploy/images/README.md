# Container images

One image per deployable process and one tools image per zone, built from one Dockerfile ([`Dockerfile`](Dockerfile), one target per image). This is the contract the Kubernetes charts implement: what each image holds, and what it expects at run time. Nothing is pushed or signed from a pull request.

| Image | Zone | Binaries | Base (digest-pinned) | C libraries it needs |
|---|---|---|---|---|
| `qv-core` | business | `qv-core` | distroless `cc-debian13` | glibc (cgo: secp256k1) |
| `qv-worker` | business | `qv-worker` | `cc-debian13` | glibc (cgo: secp256k1) |
| `qv-relay` | business | `qv-relay` | distroless `static-debian13` | none (`CGO_ENABLED=0`) |
| `qv-anchor-archiver` | business | `qv-anchor-archiver` | `static-debian13` | none |
| `qv-migrate` | business | `qv-migrate` | `static-debian13` | none |
| `qv-approval-web` | business | `qv-approval-web` and the page's files in `/srv/approval` | distroless `static-debian13` | none (`CGO_ENABLED=0`) |
| `qv-tools-business` | business | `qv-guardian`, `qv-sol-nonces` | `cc-debian13` | glibc |
| `qv-gateway` | signing | `qv-gateway` | `cc-debian13` | glibc; `dlopen` of the HSM's PKCS#11 module (not in the image) |
| `qv-cosigner` | signing | `qv-cosigner` | `cc-debian13` | glibc; PKCS#11 as above |
| `mpc-party` | signing | `mpc-party` (also `mpc-party backup …`) | `cc-debian13` | glibc, libstdc++; cb-mpc and OpenSSL are linked in statically; PKCS#11 module not in the image |
| `qv-attest-broker` | signing | `qv-attest-broker` (also `allowlist …`, `audit verify`) | `cc-debian13` | glibc; `dlopen` of the HSM's PKCS#11 module (not in the image); no cb-mpc |
| `qv-tools-signing` | signing | `qv-route`, `qv-fee-caps`, `qv-approvers`, `qv-btc-xpub`, `qv-keysets`, `qv-migrate` | `cc-debian13` | glibc |
| `qv-gateway-dev`, `qv-cosigner-dev`, `mpc-party-dev`, `qv-attest-broker-dev` | signing, **development only** | as above | `ubuntu:24.04` + SoftHSM2 | glibc, libstdc++, SoftHSM2 at `/usr/lib/softhsm/libsofthsm2.so` |

**Not images.** `qv-cold` is the offline signer: it never runs in a cluster. `qv-pki` is the development CA (`scripts/pki.sh`); production certificates come from cert-manager. `qv-attest-broker` runs beside each party's HSM (signing zone); `qv-approval-web` runs in the business cluster, on its own origin. `qv-migrate` is also in `qv-tools-signing`, for `-zone signing` (the guard databases' roles): it is a schema tool, and the business migrations embedded in it are public SQL that give no access. It is the one allowed business binary in a signing image (`QV_ZONE_ALLOW` in `images.sh`).

Rules every image follows:

- **Zones do not mix.** A signing image holds no business binary and the other way round; `check-secrets.sh` fails the build if one does.
- **Non-root:** uid/gid `65532` (`nonroot`). **No shell, no package manager.** Nothing writes outside a declared volume, so `readOnlyRootFilesystem: true` works.
- **No test-only code.** No `-tags devauth` (no insecure sealer, no `dev-allow-all` authorizer, no crash failpoints), no `teesim` (the broker's mock attester and test roots), no SoftHSM in the production images. `smoke.sh` looks for those strings in the binaries.
- **No secret in any layer.** No key, PIN, certificate, token store or `.env`. The build context is an allow-list ([`Dockerfile.dockerignore`](Dockerfile.dockerignore)); `check-secrets.sh` scans the file names of every layer.
- **Configuration is flags, environment variables and mounted files.** Defaults that point at `127.0.0.1` stay (the chart overrides them); the image exports no default of its own.

## Build and check

```bash
make images                         # every image and the -dev variants, into the local Docker, tagged qv-image/<name>:local
deploy/images/smoke.sh              # every binary runs -h as non-root, read-only, no network; no test-only code inside
deploy/images/check-secrets.sh      # no secret-looking file in any layer, no other-zone binary, non-root user
deploy/images/build.sh repro        # builds every binary twice from scratch and compares SHA-256
```

The first build compiles cb-mpc (several minutes). CI ([`images.yml`](../../.github/workflows/images.yml)) runs the same three checks on pull requests that touch image inputs. A release (manual; version tag on `main`, green CI) is described in [`docs/runbooks/release.md`](../../docs/runbooks/release.md) and summarised in "Releases" below.

## Releases

Only the production images are released (`qv_release_images` in `images.sh`); the `-dev` images are never published. The `images.yml` workflow has three release jobs:

| Job | When | What |
|---|---|---|
| `dry-run` | every pull request, and a manual run with `publish=false` | builds the release images, runs `smoke.sh` and `check-secrets.sh`, computes the digests, writes a manifest with `"dryRun": true`; read-only token, no login, no push, no signature |
| `gate` | manual run with `publish=true` | `release-gate.sh`: a tag `vMAJOR.MINOR.PATCH[-rc.N]`, whose commit is on `main` and has a successful `ci` push run |
| `publish` | after `gate`, `build` and `repro` | the same build and checks, then `publish.sh` with `PUBLISH=1`: push by digest with SBOM and provenance, cosign keyless signature, signed `release-<version>.json`; then a re-check of the pushed images (`check-secrets.sh`, `verify-release.sh`) |

Scripts: `publish.sh` (build, push, sign, manifest; dry run unless `PUBLISH=1`), `release-gate.sh`, `verify-release.sh` (a manifest against the registry), `manifest-values.py` (a manifest into the `images:` values of `qv-business`, `qv-party` and `qv-signing-core`; `ci/helm/release_values_test.go` renders them with each chart). Images carry the labels `org.opencontainers.image.source`, `.revision` and `.version`. `QV_CHECK_SET=release` makes `build.sh`, `smoke.sh` and `check-secrets.sh` handle the production images only.

## Reproducibility

- Pinned: base images by digest; Go by version and SHA-256 per architecture (the version must equal the highest `go` line of the `go.mod` files: `build.sh` refuses otherwise); cb-mpc at `mpc-party/cbmpc.pin` through `mpc-party/scripts/fetch-build-cbmpc.sh`, the same script the CI image runs; Go modules by `go.sum`.
- Flags: `-trimpath -buildvcs=false -ldflags "-s -w -buildid="`, `-mod=readonly`, `GOTOOLCHAIN=local`.
- **Not pinned: the apt packages of the build stage.** Exactly these, installed by `mpc-party/scripts/install-toolchain-linux.sh` (shared with developers and `ci/qv-ci.Dockerfile`; that file is outside the image task) and one `apt-get` line of the `toolchain` stage:
  - from the Ubuntu 24.04 archive, at whatever version the day's index has: `ca-certificates curl gnupg git cmake ninja-build make perl xz-utils g++` (and their dependencies, among them the libc headers and libstdc++ that cgo and cb-mpc compile against);
  - from `apt.llvm.org`: `clang-20` (the repository's key is checked against its published fingerprint, the packages are not pinned: that repository keeps only the newest 20.x, so an exact version disappears, and it has no dated snapshots).
  Why not pinned: the only complete pin is a dated snapshot mirror of both archives plus a copy of the LLVM packages, which needs hosting and a change to the shared install script; that is more than this task. Effect: a build months later can pick another clang or libc header, so the cgo parts of a binary (secp256k1, the PKCS#11 binding, cb-mpc) can differ, and `build.sh repro` holds only for builds close in time. The pure-Go binaries (the three `static` images and `qv-approval-web`) do not use these packages. Pin by snapshot before a TEE measurement has to survive a rebuild.
- `SOURCE_DATE_EPOCH` (default: commit time of `HEAD`) is passed to BuildKit with `rewrite-timestamp`, which clamps every file time in the layers and sets the image creation time. Measured on one machine (linux/arm64, Docker 29, BuildKit 0.34): two builds from scratch (`--no-cache`) gave identical SHA-256 for all 14 binaries (before `qv-attest-broker` and `qv-approval-web` were added; CI's `repro` job covers 16 now) (`build.sh repro`), and two from-scratch builds of the `qv-core` image exported as OCI (`--output type=oci,rewrite-timestamp=true`) gave the **same image digest**. What still differs: the image ID changes when `SOURCE_DATE_EPOCH` changes (a new commit), and anything built with a different clang (see above), another architecture (amd64 and arm64 binaries differ; each is reproducible on its own), or without `rewrite-timestamp` (layer file times and the creation time become the build time). The `-dev` images are not reproducible: they install SoftHSM2 (and `ca-certificates`) from Ubuntu's archive by apt without a version pin.

## Run-time contract

`TLS` means the three files of one identity: `-tls-cert`, `-tls-key`, `-tls-ca` (environment `QV_TLS_CERT`, `QV_TLS_KEY`, `QV_TLS_CA`), re-read every `-tls-reload` (`QV_TLS_RELOAD`, default 1 minute). A second identity has the prefix `link-` (`-link-tls-cert`, `QV_LINK_TLS_CERT`, …). A DSN names its own client certificate files (`sslcert`, `sslkey`, `sslrootcert`); those files must be readable by uid 65532 too. Metrics are plain http and **loopback only** by default (`pki.RequireLoopback`): a business-zone service (`qv-core`, `qv-relay`, `qv-anchor-archiver`) may bind another address, e.g. the pod address, only with `QV_METRICS_ALLOW_NON_LOOPBACK=1`; signing-zone services never (a sidecar reads them; decision D12, runbook `certificates.md`).

| Image | Command | Flags and environment | Files it reads | Writes | Listens |
|---|---|---|---|---|---|
| `qv-core` | `qv-core` | `-config` (required), `-addr` / `QV_HTTP_ADDR` (default `127.0.0.1:8080`), `-dsn` / `DATABASE_URL`, `-temporal` / `QV_TEMPORAL_ADDR`, `-namespace`, `-task-queue`, `-oidc-issuer` / `QV_OIDC_ISSUER`, `-oidc-audience` / `QV_OIDC_AUDIENCE`, `-oidc-jwks-url` / `QV_OIDC_JWKS_URL`, `-oidc-roles-claim` / `QV_OIDC_ROLES_CLAIM`, `-oidc-role-map` / `QV_OIDC_ROLE_MAP`, `-oidc-service-clients` / `QV_OIDC_SERVICE_CLIENTS`, `-oidc-stepup-acr` / `QV_OIDC_STEPUP_ACR`, `-oidc-stepup-max-age`, `-oidc-max-session`, `-service-allow` / `QV_CORE_SERVICE_ALLOW`, `-approval-origins` / `QV_APPROVAL_ORIGINS` (origins of the approval page; off when empty), `-metrics-listen` / `QV_CORE_METRICS_LISTEN`, `-health-listen` / `QV_HEALTH_LISTEN`, `QV_METRICS_ALLOW_NON_LOOPBACK`, `QV_ENV` (unset = production), TLS | custody config JSON; TLS files; `-oidc-ca-file` / `QV_OIDC_CA_FILE` (CA bundle of a private IdP); the DSN's client certificate files | nothing | HTTPS on `-addr`; metrics on a loopback address |
| `qv-worker` | `qv-worker` | `-config` (required), `-dsn` / `DATABASE_URL`, `-temporal` / `QV_TEMPORAL_ADDR`, `-namespace`, `-task-queue`, `-auto-approver-key-file` / `QV_AUTO_APPROVER_KEY_FILE`, `-watchdog-stall`, `-watchdog-interval`, `-stop-timeout` (default 40 s), `-health-listen` / `QV_HEALTH_LISTEN`, TLS | custody config JSON; the approver seed file (64 hex chars); TLS files; DSN certificate files | nothing | nothing |
| `qv-relay` | `qv-relay` | `-dsn` / `DATABASE_URL`, `-brokers` / `QV_KAFKA_BROKERS`, `-audit-source`, `-anchor-interval`, `-prune-retention`, `-prune-interval`, `-prune-batch`, `-batch`, `-idle`, `-metrics-listen`, `-health-listen` / `QV_HEALTH_LISTEN`, `QV_METRICS_ALLOW_NON_LOOPBACK`, TLS | TLS files (used for Kafka too); DSN certificate files | nothing | metrics on a loopback address |
| `qv-anchor-archiver` | `qv-anchor-archiver` | `-brokers` / `QV_KAFKA_BROKERS`, `-group`, `-retention` (default 7 years), `-metrics-listen`, `-health-listen` / `QV_HEALTH_LISTEN`, `QV_METRICS_ALLOW_NON_LOOPBACK`, `-archive-endpoint` / `QV_ARCHIVE_ENDPOINT`, `-archive-bucket` / `QV_ARCHIVE_BUCKET`, `-archive-region` / `QV_ARCHIVE_REGION`, `-archive-path-style`, `QV_ARCHIVE_ACCESS_KEY` or `QV_ARCHIVE_ACCESS_KEY_FILE`, `QV_ARCHIVE_SECRET_KEY` or `QV_ARCHIVE_SECRET_KEY_FILE`, TLS, `-archive-tls-*` for an https store | TLS files; the two key files if `_FILE` is used | nothing | metrics on a loopback address |
| `qv-migrate` | `qv-migrate` (a Job) | `-zone business\|signing`, `-dsn` / `DATABASE_URL` or `QV_SIGNING_DB_URL` (owner role), `-enable-login` (development only) | the DSN's certificate files (the admin certificate) | nothing (the database) | nothing |
| `qv-approval-web` | `qv-approval-web` | `-listen` / `QV_APPROVAL_LISTEN` (default `127.0.0.1:8090`), `-dir` / `QV_APPROVAL_DIR` (the page's files; **the image has them in `/srv/approval`, the default `web/approval` does not exist there, so set it**), `-issuer` / `QV_OIDC_ISSUER`, `-client-id` / `QV_APPROVAL_CLIENT_ID` (default `qv-approval`), `-api` / `QV_APPROVAL_API` (origin of the core's API), `-asset-decimals` / `QV_APPROVAL_ASSET_DECIMALS`, `-max-login-age`, `-tls-cert`, `-tls-key` (only to serve https itself; behind an ingress it serves plain http) | the page's files in the image (read-only); with `-tls-cert`, the two files | nothing (it writes `/config.json` from its flags in memory) | http (or https with `-tls-cert`) on `-listen`; no health listener: probe `GET /config.json` |
| `qv-tools-business` | none: the Job names `/usr/local/bin/qv-guardian` or `qv-sol-nonces` | `qv-guardian freeze -rpc -factory -key-file -core -actor`; `qv-sol-nonces -config -dsn / DATABASE_URL -shard -action -index -approver -approver-key -wait`; `QV_CORE_TOKEN` or `QV_OIDC_*` for the core | guardian key file; custody config; approver key file | nothing | nothing |
| `qv-gateway` | `qv-gateway` | `-config` (required), `-jobs-dsn` / `QV_GATEWAY_JOBS_DSN`, `-guard-dsn` / `QV_GATEWAY_GUARD_DSN` (a different database), `-brokers` / `QV_KAFKA_BROKERS`, `-audit-source`, `-anchor-interval`, `-interval`, `-lease`, `-worker-id`, `-mpc-metrics-file` / `QV_MPC_METRICS_FILE`, `-health-listen` / `QV_HEALTH_LISTEN`, TLS (signing zone) and link TLS (business CA): `-link-tls-cert`, `-link-tls-key`, `-link-tls-ca`, `-link-tls-reload` / `QV_LINK_TLS_CERT`, `QV_LINK_TLS_KEY`, `QV_LINK_TLS_CA`, `QV_LINK_TLS_RELOAD`, `QV_ENV` (dev only), `QV_PKCS11_LIB` and `QV_HSM_PIN_FILE` (the file that holds the PIN; the environment form of the PIN is refused unless `QV_ENV` is dev or test) only for HSM signers, `SOFTHSM2_CONF` (-dev) | signing config JSON (approvers, bounds, party addresses and pins); TLS and link files; the PKCS#11 module and the PIN file if HSM signers are configured | the metrics file, written as `<file>.tmp` then renamed: **its directory must be a writable volume** (`/var/lib/qv/metrics` is provided, owned by 65532) | nothing: it dials out (business DB, Kafka, parties A and B) |
| `qv-cosigner` | `qv-cosigner` | `-config` (required), `-socket` (required), `-guard-dsn` / `QV_COSIGNER_GUARD_DSN`, `-gateway-guard-dsn` / `QV_GATEWAY_GUARD_DSN` (refusal check), `-brokers`, `-audit-source`, `-anchor-interval`, `-socket-cert` / `QV_COSIGNER_SOCKET_CERT`, `-socket-key` / `QV_COSIGNER_SOCKET_KEY`, `-party-pins` / `QV_COSIGNER_PARTY_PINS`, `-metrics-listen` / `QV_COSIGNER_METRICS_LISTEN`, TLS and `link-` TLS (`-tls-cert`, `-tls-key`, `-tls-ca`, `-tls-reload`, `-link-tls-cert`, `-link-tls-key`, `-link-tls-ca`, `-link-tls-reload`; environment `QV_TLS_*`, `QV_LINK_TLS_CERT`, `QV_LINK_TLS_KEY`, `QV_LINK_TLS_CA`, `QV_LINK_TLS_RELOAD`), `-health-listen` / `QV_HEALTH_LISTEN`, `QV_KAFKA_BROKERS` | signing config of its side; socket cert and key; TLS and link files | the unix socket, mode 0600, **owner only**: it must sit on a shared volume (`/run/qv`, an `emptyDir` in the pod), and the party container must run as the **same uid** | unix socket `-socket`; metrics on a loopback address |
| `mpc-party` | `mpc-party -config FILE` (or `mpc-party backup …`) | only `-config`. Everything else is in the JSON file (`mpc-party/internal/server/config.go`): `role` A, B or C, `caller_listen`, `peer_listen`, `peer_address`, `peer_c_address`, pins, `data_dir`, `metrics_listen`, `admin_keys`, `sealer` (`type` `pkcs11`, `token`, `lib`, `pin_env` or `pin_file`), `authorizer` (`pinned-caller` for A, `cosigner` with `socket` and `cosigner_pins` for B and C), `limits` | the config; `cert_file` and `key_file`; the PIN file or `pin_env`'s variable; the PKCS#11 module at `sealer.lib` | `data_dir`: sealed shares, freeze records, generations, stored signatures (`/var/lib/qv/party` is provided, mode 0750, owned by 65532; a `ReadWriteOncePod` volume); `.tmp-*` files next to the files it replaces | gRPC `caller_listen` (mTLS, callers pinned), gRPC `peer_listen` (mTLS, peers pinned), `metrics_listen` (plain http, no loopback rule); dials `/run/qv/cosigner.sock` (B, C) |
| `qv-attest-broker` | `qv-attest-broker serve -config FILE` (also `allowlist keygen\|new\|sign\|show`, `audit verify`) | only `-config` for `serve`. Everything else is in the JSON file (`mpc-party/internal/attest/broker/config.go`): `listen` (mutual TLS), `health_listen` (plain http `/healthz`, `/metrics`), `tls_cert`, `tls_key`, `pkcs11` (module, token, PIN file), `trust_roots`, `allowlist_file`, `operators`, `parties` (caller pins), `audit_log`, `reload_interval`, `rate_per_minute` | the config; TLS key; the PIN file; the PKCS#11 module; the signed allowlist and the trust-roots file; the PKCS#11 module is not in the image | the audit log (hash-chained, fsynced): **its directory must be a writable volume** (`/var/lib/qv/broker` is provided, mode 0750, owned by 65532); reloads on `SIGHUP` and by polling | mutual TLS on `listen`; `health_listen` (pod address for the probe; no data, no auth) |
| `qv-tools-signing` | none: the Job names `/usr/local/bin/<tool>` | `qv-migrate -zone signing -dsn / QV_SIGNING_DB_URL` (owner role of the guard database; **a Job in each signing cluster, run by that cluster's operators**; never `-enable-login` in production); `qv-route show\|sign\|apply -config -guard-dsn / QV_GATEWAY_GUARD_DSN`; `qv-fee-caps show\|sign\|apply\|metrics -config -chain -guard-dsn -core-dsn / QV_CORE_DSN -out`; `qv-approvers show\|sign\|apply -config -guard-dsn`; `qv-keysets show\|sign\|apply -config -guard-dsn` (`sign` takes `-operator -key -seq -shard -generation -action`, on the operator's machine); `qv-btc-xpub -party -cert -key -server-pin -keyset -network -shards` | signing config; guard DSN certificate files; the guard DSN's admin certificate files (`qv-migrate`); approver or operator key files (given only for `sign`, which belongs on the person's machine, not in a cluster); a client cert for `qv-btc-xpub` | `-out FILE` of the tool (the Job's volume) | nothing |

All images: user `65532:65532`, `ENTRYPOINT` as the table says (none for the tools images), no `CMD`, no `VOLUME`, no `EXPOSE` (the ports are configuration). Directories that exist and belong to 65532: `/var/lib/qv/party`, `/var/lib/qv/broker`, `/var/lib/qv/metrics`, `/run/qv`, `/etc/qv` (in the images that use them). Mount volumes there, or elsewhere and set the flag.

### Probes, shutdown, state (D2)

**Probes.** `qv-core`, `qv-worker`, `qv-relay`, `qv-anchor-archiver`, `qv-gateway`, `qv-cosigner`: `-health-listen` / `QV_HEALTH_LISTEN` (off when empty; use `0.0.0.0:9100`): plain http, `GET /livez` (always 200) and `GET /readyz` (200, or 503 with the body `not ready`, no detail). Nothing else is served on that port. `mpc-party`: the same, flag `-health-listen` / `QV_HEALTH_LISTEN` (its gRPC `Health` is on the mutual-TLS caller port, which a kubelet gRPC probe cannot use). Use `httpGet` probes: `livenessProbe` on `/livez`, `readinessProbe` and `startupProbe` on `/readyz`. Separate listener rather than the service port: `qv-gateway` and `qv-cosigner` have no http port, and `qv-core`'s port is TLS with client-certificate rules.

| Service | Ready means |
|---|---|
| `qv-core` | start-up finished, business database answers, certificate not expired |
| `qv-worker` | as core, and Temporal answers `CheckHealth` |
| `qv-relay` | database answers, certificate valid |
| `qv-anchor-archiver` | the bucket passed the Object Lock check and the consumer runs, certificate valid |
| `qv-gateway` | job-queue database and guard database answer, both certificates valid |
| `qv-cosigner` | guard database answers, both certificates valid, socket open |
| `mpc-party` | data directory locked, sealer open, listeners up, certificate valid; **not** the other parties |

All go "not ready" the moment SIGTERM arrives.

**Stop (SIGTERM).** Every service stops accepting, finishes what it has, exits 0. `terminationGracePeriodSeconds` must exceed:

| Service | Bound after SIGTERM | Set at least |
|---|---|---|
| `qv-core`, `qv-cosigner` | 10 s for running requests | 30 s |
| `qv-worker` | `-stop-timeout` (default 40 s): no new tasks, running activities and workflow tasks finish; sign, nonce and refill waits hand back at once; then exit 0. Still running at the bound: cut and retried by another worker (idempotent). A second signal exits 1 at once | stop-timeout + 20 s (chart: 60 s) |
| `qv-relay`, `qv-anchor-archiver` | one batch / one poll, a few seconds | 30 s |
| `qv-gateway` | `sign_timeout` of the signing config (default 30 s) for signer calls in flight; then exit **1** if one still runs (closing the HSM under it would crash; nothing is lost, an unstored signature was never released). Right as it is | `sign_timeout` + 30 s |
| `mpc-party` | `limits.shutdown_grace_ms` (default 10 s), then running sessions are cut | grace + 20 s |

**One process per `data_dir`.** `mpc-party` takes an exclusive `flock` on `<data_dir>/.lock` before it reads anything; a second process on the directory exits with "in use by another mpc-party process". The kernel drops the lock when the holder dies (kill -9 included). The volume must support `flock` (block volumes, `ReadWriteOncePod`; check NFS).

**PIN file.** `pin_file` may have mode 0400/0600 or be group-readable (0440/0640, a Secret volume with `fsGroup`); a world bit or a group write/execute bit is refused. The log names the accepted mode when the group can read it.

**SoftHSM.** `qv-gateway` and `mpc-party` refuse a SoftHSM PKCS#11 module unless `QV_ENV` is `dev` or `test` (unset or any other value is production). Detection is by what the module reports (library manufacturer/description, token manufacturer/model contain "softhsm"), not the file name. The `-dev` images must be run with `QV_ENV=dev`. **`qv-attest-broker` has no such check** (it never reads `QV_ENV`; found by Images-2, a follow-up for the broker's owner): a production broker pointed at a SoftHSM module would run, so the chart must never mount one, and `qv-attest-broker-dev` is the only image that contains one. `qv-cold` (offline) is not a service and is unchanged.

Secrets: PINs, private keys and DSN passwords are never in the image or in an environment dump you can avoid: mount them as files. Note for the party: `pin_file` may be group-readable but not group-writable and has no world bit (see above), so a Secret volume with `fsGroup` works. The gateway follows the same mode rule for `QV_HSM_PIN_FILE` (read once at start) and refuses a PIN in `QV_HSM_PIN` unless `QV_ENV` is dev or test.

## For the TEE measurement (TEE-T1)

What a containerised party's measurement can cover, from the image side: the `mpc-party` image is the unit. Its content is exactly: the distroless `cc-debian13` base (by digest), `/usr/local/bin/mpc-party`, and three empty directories. The binary hash is reproducible given the build stage inputs (see above); the image digest is the thing a policy names. Not covered by the image: the config file, the pins, the PKCS#11 module, the certificates and the data volume. Build the enclave image (EIF) from this image's digest, not from a tag. TEE-T1 may extend this section.
