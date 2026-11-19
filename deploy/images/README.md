# Container images

One image per deployable process and one tools image per zone, built from one Dockerfile ([`Dockerfile`](Dockerfile), one target per image). This is the contract the Kubernetes charts implement: what each image holds, and what it expects at run time. Nothing is pushed or signed from a pull request.

| Image | Zone | Binaries | Base (digest-pinned) | C libraries it needs |
|---|---|---|---|---|
| `qv-core` | business | `qv-core` | distroless `cc-debian13` | glibc (cgo: secp256k1) |
| `qv-worker` | business | `qv-worker` | `cc-debian13` | glibc (cgo: secp256k1) |
| `qv-relay` | business | `qv-relay` | distroless `static-debian13` | none (`CGO_ENABLED=0`) |
| `qv-anchor-archiver` | business | `qv-anchor-archiver` | `static-debian13` | none |
| `qv-migrate` | business | `qv-migrate` | `static-debian13` | none |
| `qv-tools-business` | business | `qv-guardian`, `qv-sol-nonces` | `cc-debian13` | glibc |
| `qv-gateway` | signing | `qv-gateway` | `cc-debian13` | glibc; `dlopen` of the HSM's PKCS#11 module (not in the image) |
| `qv-cosigner` | signing | `qv-cosigner` | `cc-debian13` | glibc; PKCS#11 as above |
| `mpc-party` | signing | `mpc-party` (also `mpc-party backup …`) | `cc-debian13` | glibc, libstdc++; cb-mpc and OpenSSL are linked in statically; PKCS#11 module not in the image |
| `qv-tools-signing` | signing | `qv-route`, `qv-fee-caps`, `qv-approvers`, `qv-btc-xpub`, `qv-keysets`, `qv-migrate` | `cc-debian13` | glibc |
| `qv-gateway-dev`, `qv-cosigner-dev`, `mpc-party-dev` | signing, **development only** | as above | `ubuntu:24.04` + SoftHSM2 | glibc, libstdc++, SoftHSM2 at `/usr/lib/softhsm/libsofthsm2.so` |

**Not images.** `qv-cold` is the offline signer: it never runs in a cluster. `qv-pki` is the development CA (`scripts/pki.sh`); production certificates come from cert-manager. `qv-migrate` is also in `qv-tools-signing`, for `-zone signing` (the guard databases' roles): it is a schema tool, and the business migrations embedded in it are public SQL that give no access. It is the one allowed business binary in a signing image (`QV_ZONE_ALLOW` in `images.sh`).

Rules every image follows:

- **Zones do not mix.** A signing image holds no business binary and the other way round; `check-secrets.sh` fails the build if one does.
- **Non-root:** uid/gid `65532` (`nonroot`). **No shell, no package manager.** Nothing writes outside a declared volume, so `readOnlyRootFilesystem: true` works.
- **No test-only code.** No `-tags devauth` (no insecure sealer, no `dev-allow-all` authorizer, no crash failpoints), no `teesim`, no SoftHSM in the production images. `smoke.sh` looks for those strings in the binaries.
- **No secret in any layer.** No key, PIN, certificate, token store or `.env`. The build context is an allow-list ([`Dockerfile.dockerignore`](Dockerfile.dockerignore)); `check-secrets.sh` scans the file names of every layer.
- **Configuration is flags, environment variables and mounted files.** Defaults that point at `127.0.0.1` stay (the chart overrides them); the image exports no default of its own.

## Build and check

```bash
make images                         # every image and the -dev variants, into the local Docker, tagged qv-image/<name>:local
deploy/images/smoke.sh              # every binary runs -h as non-root, read-only, no network; no test-only code inside
deploy/images/check-secrets.sh      # no secret-looking file in any layer, no other-zone binary, non-root user
deploy/images/build.sh repro        # builds every binary twice from scratch and compares SHA-256
```

The first build compiles cb-mpc (several minutes). CI ([`images.yml`](../../.github/workflows/images.yml)) runs the same three checks on pull requests that touch image inputs. Publishing and signing (`publish.sh`: push by digest, SBOM, provenance, cosign keyless) exist only behind the manual `workflow_dispatch` input `publish`, default off.

## Reproducibility

- Pinned: base images by digest; Go by version and SHA-256 per architecture (the version must equal the highest `go` line of the `go.mod` files: `build.sh` refuses otherwise); cb-mpc at `mpc-party/cbmpc.pin` through `mpc-party/scripts/fetch-build-cbmpc.sh`, the same script the CI image runs; Go modules by `go.sum`.
- Flags: `-trimpath -buildvcs=false -ldflags "-s -w -buildid="`, `-mod=readonly`, `GOTOOLCHAIN=local`.
- Not pinned: the apt packages of the build stage (clang-20 from apt.llvm.org, Ubuntu's libc headers), as in `ci/qv-ci.Dockerfile`. A build months later can pick a newer clang, so the cgo parts of a binary can differ. Pin them by a package snapshot when the TEE measurement needs bytes that last.
- `SOURCE_DATE_EPOCH` (default: commit time of `HEAD`) is passed to BuildKit with `rewrite-timestamp`, which clamps every file time in the layers and sets the image creation time. Measured on one machine (linux/arm64, Docker 29, BuildKit 0.34): two builds from scratch (`--no-cache`) gave identical SHA-256 for all 14 binaries (`build.sh repro`), and two from-scratch builds of the `qv-core` image exported as OCI (`--output type=oci,rewrite-timestamp=true`) gave the **same image digest**. What still differs: the image ID changes when `SOURCE_DATE_EPOCH` changes (a new commit), and anything built with a different clang (see above), another architecture (amd64 and arm64 binaries differ; each is reproducible on its own), or without `rewrite-timestamp` (layer file times and the creation time become the build time). The `-dev` images are not reproducible: they install SoftHSM2 by apt without a version pin.

## Run-time contract

`TLS` means the three files of one identity: `-tls-cert`, `-tls-key`, `-tls-ca` (environment `QV_TLS_CERT`, `QV_TLS_KEY`, `QV_TLS_CA`), re-read every `-tls-reload` (`QV_TLS_RELOAD`, default 1 minute). A second identity has the prefix `link-` (`-link-tls-cert`, `QV_LINK_TLS_CERT`, …). A DSN names its own client certificate files (`sslcert`, `sslkey`, `sslrootcert`); those files must be readable by uid 65532 too. Metrics are plain http and **loopback only** (`pki.RequireLoopback`, `internal/pki/flags.go:70`): a scraper cannot reach them from outside the pod (design decision D12).

| Image | Command | Flags and environment | Files it reads | Writes | Listens |
|---|---|---|---|---|---|
| `qv-core` | `qv-core` | `-config` (required), `-addr` / `QV_HTTP_ADDR` (default `127.0.0.1:8080`), `-dsn` / `DATABASE_URL`, `-temporal` / `QV_TEMPORAL_ADDR`, `-namespace`, `-task-queue`, `QV_OIDC_ISSUER`, `QV_OIDC_AUDIENCE`, `QV_OIDC_JWKS_URL`, `QV_OIDC_ROLES_CLAIM`, `QV_OIDC_ROLE_MAP`, `QV_OIDC_SERVICE_CLIENTS`, `QV_OIDC_STEPUP_ACR`, `QV_CORE_SERVICE_ALLOW`, `-metrics-listen` / `QV_CORE_METRICS_LISTEN`, `QV_ENV` (unset = production), TLS | custody config JSON; TLS files; `QV_OIDC_CA_FILE` (CA bundle of a private IdP); the DSN's client certificate files | nothing | HTTPS on `-addr`; metrics on a loopback address |
| `qv-worker` | `qv-worker` | `-config` (required), `-dsn` / `DATABASE_URL`, `-temporal` / `QV_TEMPORAL_ADDR`, `-namespace`, `-task-queue`, `-auto-approver-key-file` / `QV_AUTO_APPROVER_KEY_FILE`, `-watchdog-stall`, `-watchdog-interval`, TLS | custody config JSON; the approver seed file (64 hex chars); TLS files; DSN certificate files | nothing | nothing |
| `qv-relay` | `qv-relay` | `-dsn` / `DATABASE_URL`, `-brokers` / `QV_KAFKA_BROKERS`, `-audit-source`, `-anchor-interval`, `-prune-retention`, `-prune-interval`, `-prune-batch`, `-batch`, `-idle`, `-metrics-listen`, TLS | TLS files (used for Kafka too); DSN certificate files | nothing | metrics on a loopback address |
| `qv-anchor-archiver` | `qv-anchor-archiver` | `-brokers` / `QV_KAFKA_BROKERS`, `-group`, `-retention` (default 7 years), `-metrics-listen`, `-archive-endpoint` / `QV_ARCHIVE_ENDPOINT`, `-archive-bucket` / `QV_ARCHIVE_BUCKET`, `-archive-region` / `QV_ARCHIVE_REGION`, `-archive-path-style`, `QV_ARCHIVE_ACCESS_KEY` or `QV_ARCHIVE_ACCESS_KEY_FILE`, `QV_ARCHIVE_SECRET_KEY` or `…_FILE`, TLS, `-archive-tls-*` for an https store | TLS files; the two key files if `_FILE` is used | nothing | metrics on a loopback address |
| `qv-migrate` | `qv-migrate` (a Job) | `-zone business\|signing`, `-dsn` / `DATABASE_URL` or `QV_SIGNING_DB_URL` (owner role), `-enable-login` (development only) | the DSN's certificate files (the admin certificate) | nothing (the database) | nothing |
| `qv-tools-business` | none: the Job names `/usr/local/bin/qv-guardian` or `qv-sol-nonces` | `qv-guardian freeze -rpc -factory -key-file -core -actor`; `qv-sol-nonces -config -dsn / DATABASE_URL -shard -action -index -approver -approver-key -wait`; `QV_CORE_TOKEN` or `QV_OIDC_*` for the core | guardian key file; custody config; approver key file | nothing | nothing |
| `qv-gateway` | `qv-gateway` | `-config` (required), `-jobs-dsn` / `QV_GATEWAY_JOBS_DSN`, `-guard-dsn` / `QV_GATEWAY_GUARD_DSN` (a different database), `-brokers` / `QV_KAFKA_BROKERS`, `-audit-source`, `-anchor-interval`, `-interval`, `-lease`, `-worker-id`, `-mpc-metrics-file` / `QV_MPC_METRICS_FILE`, TLS (signing zone) and `link-` TLS (business CA), `QV_PKCS11_LIB` and `QV_HSM_PIN` only for HSM signers, `SOFTHSM2_CONF` (-dev) | signing config JSON (approvers, bounds, party addresses and pins); TLS and link files; the PKCS#11 module if HSM signers are configured | the metrics file, written as `<file>.tmp` then renamed: **its directory must be a writable volume** (`/var/lib/qv/metrics` is provided, owned by 65532) | nothing: it dials out (business DB, Kafka, parties A and B) |
| `qv-cosigner` | `qv-cosigner` | `-config` (required), `-socket` (required), `-guard-dsn` / `QV_COSIGNER_GUARD_DSN`, `-gateway-guard-dsn` / `QV_GATEWAY_GUARD_DSN` (refusal check), `-brokers`, `-audit-source`, `-anchor-interval`, `-socket-cert` / `QV_COSIGNER_SOCKET_CERT`, `-socket-key` / `QV_COSIGNER_SOCKET_KEY`, `-party-pins` / `QV_COSIGNER_PARTY_PINS`, `-metrics-listen` / `QV_COSIGNER_METRICS_LISTEN`, TLS and `link-` TLS | signing config of its side; socket cert and key; TLS and link files | the unix socket, mode 0600, **owner only**: it must sit on a shared volume (`/run/qv`, an `emptyDir` in the pod), and the party container must run as the **same uid** | unix socket `-socket`; metrics on a loopback address |
| `mpc-party` | `mpc-party -config FILE` (or `mpc-party backup …`) | only `-config`. Everything else is in the JSON file (`mpc-party/internal/server/config.go`): `role` A, B or C, `caller_listen`, `peer_listen`, `peer_address`, `peer_c_address`, pins, `data_dir`, `metrics_listen`, `admin_keys`, `sealer` (`type` `pkcs11`, `token`, `lib`, `pin_env` or `pin_file`), `authorizer` (`pinned-caller` for A, `cosigner` with `socket` and `cosigner_pins` for B and C), `limits` | the config; `cert_file` and `key_file`; the PIN file or `pin_env`'s variable; the PKCS#11 module at `sealer.lib` | `data_dir`: sealed shares, freeze records, generations, stored signatures (`/var/lib/qv/party` is provided, mode 0750, owned by 65532; a `ReadWriteOncePod` volume); `.tmp-*` files next to the files it replaces | gRPC `caller_listen` (mTLS, callers pinned), gRPC `peer_listen` (mTLS, peers pinned), `metrics_listen` (plain http, no loopback rule); dials `/run/qv/cosigner.sock` (B, C) |
| `qv-tools-signing` | none: the Job names `/usr/local/bin/<tool>` | `qv-migrate -zone signing -dsn / QV_SIGNING_DB_URL` (owner role of the guard database; **a Job in each signing cluster, run by that cluster's operators**; never `-enable-login` in production); `qv-route show\|sign\|apply -config -guard-dsn / QV_GATEWAY_GUARD_DSN`; `qv-fee-caps show\|sign\|apply\|metrics -config -chain -guard-dsn -core-dsn / QV_CORE_DSN -out`; `qv-approvers show\|sign\|apply -config -guard-dsn`; `qv-keysets show\|sign\|apply -config -guard-dsn` (`sign` takes `-operator -key -seq -shard -generation -action`, on the operator's machine); `qv-btc-xpub -party -cert -key -server-pin -keyset -network -shards` | signing config; guard DSN certificate files; the guard DSN's admin certificate files (`qv-migrate`); approver or operator key files (given only for `sign`, which belongs on the person's machine, not in a cluster); a client cert for `qv-btc-xpub` | `-out FILE` of the tool (the Job's volume) | nothing |

All images: user `65532:65532`, `ENTRYPOINT` as the table says (none for the tools images), no `CMD`, no `VOLUME`, no `EXPOSE` (the ports are configuration). Directories that exist and belong to 65532: `/var/lib/qv/party`, `/var/lib/qv/metrics`, `/run/qv`, `/etc/qv` (in the images that use them). Mount volumes there, or elsewhere and set the flag.

Secrets: PINs, private keys and DSN passwords are never in the image or in an environment dump you can avoid: mount them as files. Note for the party: `pin_file` must have **no group or other permission bits** (`sealer_pkcs11.go:61`); Kubernetes sets group read on a Secret volume when `fsGroup` is set, which that check refuses. Use `pin_env` or see the report of task D1 (code change for D2).

## For the TEE measurement (TEE-T1)

What a containerised party's measurement can cover, from the image side: the `mpc-party` image is the unit. Its content is exactly: the distroless `cc-debian13` base (by digest), `/usr/local/bin/mpc-party`, and three empty directories. The binary hash is reproducible given the build stage inputs (see above); the image digest is the thing a policy names. Not covered by the image: the config file, the pins, the PKCS#11 module, the certificates and the data volume. Build the enclave image (EIF) from this image's digest, not from a tag. TEE-T1 may extend this section.
