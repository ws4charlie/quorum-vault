# Production images of QuorumVault: one target per deployable, one tools image per zone. Build context: the repository root.
#
#   docker buildx build -f deploy/images/Dockerfile --target qv-core .        (deploy/images/build.sh builds all of them; `make images`)
#
# Zones never mix: a final stage copies only its own zone's binaries out of the build stages.
#   business   qv-core qv-worker qv-relay qv-anchor-archiver qv-migrate qv-tools-business (qv-guardian qv-sol-nonces)
#   signing    qv-gateway qv-cosigner mpc-party qv-tools-signing (qv-route qv-fee-caps qv-approvers qv-btc-xpub qv-migrate)
#   not images qv-cold (offline), qv-pki (development CA, scripts/pki.sh)
#
# Production images contain no test-only code (no -tags devauth: no insecure sealer, no dev authorizer, no failpoints), no SoftHSM, and no secret,
# key, PIN, certificate or .env value in any layer (the repository is public; deploy/images/check-secrets.sh enforces it). The `-dev` targets add
# SoftHSM2 for local clusters and nothing else.
#
# Reproducible: pinned bases (by digest), pinned Go (by SHA-256), cb-mpc at mpc-party/cbmpc.pin through the repository's own script, -trimpath,
# -buildvcs=false, an empty build id. Pass SOURCE_DATE_EPOCH (see build.sh) so file times in the layers and the image's creation time are fixed.
# Not pinned: the apt packages of the build stage (clang-20 from apt.llvm.org and Ubuntu's libc headers), exactly as in ci/qv-ci.Dockerfile.

# distroless 'static' (no libc) and 'cc' (glibc + libstdc++), debian13, nonroot (uid 65532), as of 2026-11-19. Multi-arch index digests.
ARG STATIC_BASE=gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
ARG CC_BASE=gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2
# ubuntu:24.04 as of 2026-11-07 (the digest ci/qv-ci.Dockerfile uses): the build stages and the -dev images.
ARG UBUNTU_BASE=ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

# ---------------------------------------------------------------------------------------------------------------------------------------------
# toolchain: clang-20 + cmake + ninja (mpc-party/scripts/install-toolchain-linux.sh, the CI recipe) and Go (the version the go.mod files ask for).
FROM ${UBUNTU_BASE} AS toolchain
ENV DEBIAN_FRONTEND=noninteractive
COPY mpc-party/scripts/install-toolchain-linux.sh /src/mpc-party/scripts/install-toolchain-linux.sh
RUN /src/mpc-party/scripts/install-toolchain-linux.sh \
 && apt-get install -y -qq --no-install-recommends g++ >/dev/null \
 && rm -rf /var/lib/apt/lists/*
# Go: the highest `go` line of the go.mod files (ci/image-tag.sh --go-version), checked against the SHA-256 below (from go.dev/dl, 2026-11-19).
ARG GO_VERSION=1.26.10
ARG GO_SHA256_AMD64=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5
ARG GO_SHA256_ARM64=3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797
RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) want="$GO_SHA256_AMD64" ;; arm64) want="$GO_SHA256_ARM64" ;; *) echo "unsupported arch $arch" >&2; exit 1 ;; esac; \
    f="go${GO_VERSION}.linux-${arch}.tar.gz"; \
    curl -fsSLo "/tmp/$f" "https://go.dev/dl/$f"; \
    echo "$want  /tmp/$f" | sha256sum -c -; \
    tar -C /usr/local -xzf "/tmp/$f"; rm -f "/tmp/$f"
ENV PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPATH=/go CC=clang-20 CXX=clang++-20

# ---------------------------------------------------------------------------------------------------------------------------------------------
# cbmpc: cb-mpc at the pinned commit, static OpenSSL and libcbmpc.a, by the repository's own script (the same recipe as `make mpc-build` and the CI image).
FROM toolchain AS cbmpc
COPY mpc-party/cbmpc.pin /src/mpc-party/cbmpc.pin
COPY mpc-party/scripts/fetch-build-cbmpc.sh /src/mpc-party/scripts/fetch-build-cbmpc.sh
RUN /src/mpc-party/scripts/fetch-build-cbmpc.sh \
 && rm -rf /src/mpc-party/.deps/cb-mpc/build /src/mpc-party/.deps/openssl-work

# ---------------------------------------------------------------------------------------------------------------------------------------------
# src: the modules' dependencies first (a cached layer), then the sources. Only what deploy/images/Dockerfile.dockerignore lets through.
FROM toolchain AS src
WORKDIR /src
COPY go.mod go.sum ./
COPY mpc-party/api/go.mod mpc-party/api/go.sum* mpc-party/api/
COPY mpc-party/go.mod mpc-party/go.sum mpc-party/
RUN --mount=type=cache,target=/go/pkg/mod go mod download && (cd mpc-party && go mod download)
COPY . .

# build flags shared by every binary: no host paths, no VCS stamp, no build id, stripped. CGO_ENABLED=1 where a binary needs glibc (see the table in
# deploy/images/README.md), 0 for the three that need nothing from C.
ENV GOFLAGS="-mod=readonly -trimpath -buildvcs=false" LDFLAGS="-s -w -buildid="

# gobin-static: no cgo anywhere in these (go list -deps shows no cgo package): static binaries for the `static` base.
FROM src AS gobin-static
RUN --mount=type=cache,target=/go/pkg/mod set -eu; mkdir -p /out; \
    for c in qv-relay qv-anchor-archiver qv-migrate; do \
      CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/$c ./cmd/$c; \
    done

# gobin-cgo: cgo (go-ethereum's secp256k1, and miekg/pkcs11, which dlopens the HSM module): dynamic against glibc, for the `cc` base.
# Same crypto code as the tests run with (CGO_ENABLED=1 is the repository's own setting, Makefile).
FROM src AS gobin-cgo
RUN --mount=type=cache,target=/go/pkg/mod set -eu; mkdir -p /out; \
    for c in qv-core qv-worker qv-guardian qv-sol-nonces qv-gateway qv-cosigner qv-route qv-fee-caps qv-approvers qv-btc-xpub; do \
      CGO_ENABLED=1 go build -ldflags "$LDFLAGS" -o /out/$c ./cmd/$c; \
    done

# gobin-party: mpc-party (its own module): cgo, cb-mpc static, libstdc++ and glibc dynamic.
FROM src AS gobin-party
COPY --from=cbmpc /src/mpc-party/.deps /src/mpc-party/.deps
RUN --mount=type=cache,target=/go/pkg/mod set -eu; mkdir -p /out; cd mpc-party; \
    CGO_ENABLED=1 go build -ldflags "$LDFLAGS" -o /out/mpc-party ./cmd/mpc-party

# bins: every binary, for the reproducibility check (build.sh repro). Not an image.
FROM scratch AS bins
COPY --from=gobin-static /out/ /
COPY --from=gobin-cgo /out/ /
COPY --from=gobin-party /out/ /

# dirs: empty directories owned by the non-root user, for the volumes the charts mount (a distroless image has no shell to make them).
FROM ${UBUNTU_BASE} AS dirs
RUN mkdir -p /d/var/lib/qv/party /d/var/lib/qv/metrics /d/run/qv /d/etc/qv && chown -R 65532:65532 /d && chmod 0750 /d/var/lib/qv/party /d/run/qv

# ---------------------------------------------------------------------------------------------------------------------------------------------
# Business zone. Config: flags or the environment (README.md). No shell, no package manager, uid 65532, nothing writes outside a mounted volume.
FROM ${CC_BASE} AS qv-core
COPY --from=gobin-cgo /out/qv-core /usr/local/bin/qv-core
ENTRYPOINT ["/usr/local/bin/qv-core"]

FROM ${CC_BASE} AS qv-worker
COPY --from=gobin-cgo /out/qv-worker /usr/local/bin/qv-worker
ENTRYPOINT ["/usr/local/bin/qv-worker"]

FROM ${STATIC_BASE} AS qv-relay
COPY --from=gobin-static /out/qv-relay /usr/local/bin/qv-relay
ENTRYPOINT ["/usr/local/bin/qv-relay"]

FROM ${STATIC_BASE} AS qv-anchor-archiver
COPY --from=gobin-static /out/qv-anchor-archiver /usr/local/bin/qv-anchor-archiver
ENTRYPOINT ["/usr/local/bin/qv-anchor-archiver"]

FROM ${STATIC_BASE} AS qv-migrate
COPY --from=gobin-static /out/qv-migrate /usr/local/bin/qv-migrate
ENTRYPOINT ["/usr/local/bin/qv-migrate"]

# Operator tools of the business zone. No entrypoint: a Job or `kubectl exec` names the tool.
FROM ${CC_BASE} AS qv-tools-business
COPY --from=gobin-cgo /out/qv-guardian /out/qv-sol-nonces /usr/local/bin/

# ---------------------------------------------------------------------------------------------------------------------------------------------
# Signing zone. The PKCS#11 module of a real HSM is not in the image: the chart mounts it (QV_PKCS11_LIB, sealer.lib).
FROM ${CC_BASE} AS qv-gateway
COPY --from=dirs /d/var/lib/qv/metrics /var/lib/qv/metrics
COPY --from=gobin-cgo /out/qv-gateway /usr/local/bin/qv-gateway
ENTRYPOINT ["/usr/local/bin/qv-gateway"]

FROM ${CC_BASE} AS qv-cosigner
COPY --from=dirs /d/run/qv /run/qv
COPY --from=gobin-cgo /out/qv-cosigner /usr/local/bin/qv-cosigner
ENTRYPOINT ["/usr/local/bin/qv-cosigner"]

FROM ${CC_BASE} AS mpc-party
COPY --from=dirs /d/var/lib/qv/party /var/lib/qv/party
COPY --from=dirs /d/run/qv /run/qv
COPY --from=gobin-party /out/mpc-party /usr/local/bin/mpc-party
ENTRYPOINT ["/usr/local/bin/mpc-party"]

# Operator tools of the signing zone. No entrypoint. qv-keysets joins here when it merges (K2a): add it to gobin-cgo's list and to the COPY below.
FROM ${CC_BASE} AS qv-tools-signing
COPY --from=gobin-cgo /out/qv-route /out/qv-fee-caps /out/qv-approvers /out/qv-btc-xpub /usr/local/bin/
# qv-migrate is a schema tool, not a business service: the signing clusters run it as a Job (-zone signing) for their guard databases' roles. Its embedded business
# migrations are public SQL and give no access. The one allowed exception to "no business binary in a signing image" (check-secrets.sh, ZONE_ALLOW).
COPY --from=gobin-static /out/qv-migrate /usr/local/bin/qv-migrate

# ---------------------------------------------------------------------------------------------------------------------------------------------
# Development variants (tag suffix -dev): the production image plus SoftHSM2, for local and kind clusters. Never deployed to production.
# Same binary, same flags; the chart points QV_PKCS11_LIB / sealer.lib at /usr/lib/softhsm/libsofthsm2.so and SOFTHSM2_CONF at a mounted config.
# Built on the same Ubuntu as the build stage (SoftHSM needs libssl, libstdc++ and apt). Non-root, uid 65532.
FROM ${UBUNTU_BASE} AS dev-base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends softhsm2 ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && (userdel -r ubuntu 2>/dev/null || true) \
 && groupadd -g 65532 qv && useradd -u 65532 -g 65532 -M -d /nonexistent -s /usr/sbin/nologin qv \
 && mkdir -p /var/lib/qv/party /var/lib/qv/metrics /run/qv /etc/qv && chown -R 65532:65532 /var/lib/qv /run/qv /etc/qv \
 && chmod 0750 /var/lib/qv/party /run/qv
USER 65532:65532

FROM dev-base AS qv-gateway-dev
COPY --from=gobin-cgo /out/qv-gateway /usr/local/bin/qv-gateway
ENTRYPOINT ["/usr/local/bin/qv-gateway"]

FROM dev-base AS qv-cosigner-dev
COPY --from=gobin-cgo /out/qv-cosigner /usr/local/bin/qv-cosigner
ENTRYPOINT ["/usr/local/bin/qv-cosigner"]

FROM dev-base AS mpc-party-dev
COPY --from=gobin-party /out/mpc-party /usr/local/bin/mpc-party
ENTRYPOINT ["/usr/local/bin/mpc-party"]
