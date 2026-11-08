# The CI image: the tools and libraries the end-to-end jobs need, built once per set of inputs instead of in every job.
#
#   clang-20 + cmake + ninja   mpc-party/scripts/install-toolchain-linux.sh   (the same script a developer runs on Linux)
#   cb-mpc at the pinned commit mpc-party/scripts/fetch-build-cbmpc.sh at mpc-party/cbmpc.pin   (the same recipe as `make mpc-build`)
#   SoftHSM2, make, jq, git, curl, Go (the highest version a go.mod asks for), the docker CLI with the compose plugin (the tests restart the compose bitcoind)
#
# Tools and libraries only. No SoftHSM token, PIN, key, share, certificate or .env value is in any layer: the tokens are made at job time by
# scripts/setup-softhsm.sh, in the checkout. The image is public (the repository is): nothing private may ever be added here.
#
# The tag is a hash of every input (ci/image-tag.sh), so an image can never be stale. Build it with ci/ensure-image.sh. Only the files named in
# ci/qv-ci.Dockerfile.dockerignore enter the build context.
#
# Base images are pinned by digest (the multi-arch index, so a developer's arm64 build and CI's amd64 build both resolve).
# ubuntu:24.04 and docker:27-cli as of 2026-11-07.
FROM docker:27-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c AS dockercli

FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
LABEL org.opencontainers.image.source="https://github.com/ws4charlie/quorum-vault" \
      org.opencontainers.image.description="Tools and libraries for the quorum-vault CI jobs (clang-20, cb-mpc, SoftHSM2, Go). No secrets." \
      org.opencontainers.image.licenses="NOASSERTION"
ENV DEBIAN_FRONTEND=noninteractive

# 1. The C++ toolchain, from the repository's own script. g++ is only for libstdc++'s headers and library, which clang uses.
COPY mpc-party/scripts/install-toolchain-linux.sh /opt/qv-ci/mpc-party/scripts/install-toolchain-linux.sh
RUN /opt/qv-ci/mpc-party/scripts/install-toolchain-linux.sh \
 && apt-get install -y -qq --no-install-recommends g++ softhsm2 make jq xz-utils >/dev/null \
 && rm -rf /var/lib/apt/lists/*

# 2. cb-mpc (static OpenSSL and libcbmpc.a) at the pinned commit, in /opt/qv-ci/mpc-party/.deps. A job links /opt/qv-ci/mpc-party/.deps as
#    mpc-party/.deps of its checkout. The build tree (several hundred MB of objects) is deleted; headers and libraries stay.
COPY mpc-party/cbmpc.pin /opt/qv-ci/mpc-party/cbmpc.pin
COPY mpc-party/scripts/fetch-build-cbmpc.sh /opt/qv-ci/mpc-party/scripts/fetch-build-cbmpc.sh
RUN CC=clang-20 CXX=clang++-20 /opt/qv-ci/mpc-party/scripts/fetch-build-cbmpc.sh \
 && rm -rf /opt/qv-ci/mpc-party/.deps/cb-mpc/build /opt/qv-ci/mpc-party/.deps/openssl-work \
 && chmod -R a+rX /opt/qv-ci

# 3. Go: the highest version any go.mod of the repository asks for (ci/image-tag.sh). The tarball is checked against the SHA-256 that go.dev publishes for it.
ARG GO_VERSION
RUN set -eu; \
    test -n "$GO_VERSION"; \
    arch="$(dpkg --print-architecture)"; f="go${GO_VERSION}.linux-${arch}.tar.gz"; \
    curl -fsSLo "/tmp/$f" "https://go.dev/dl/$f"; \
    want="$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all' | jq -r --arg f "$f" '.[].files[] | select(.filename==$f) | .sha256')"; \
    test -n "$want"; echo "$want  /tmp/$f" | sha256sum -c -; \
    tar -C /usr/local -xzf "/tmp/$f"; rm -f "/tmp/$f"

# 4. The docker CLI and the compose plugin (the recovery tests run `docker compose restart bitcoind` against the runner's daemon).
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

ENV PATH=/usr/local/go/bin:$PATH \
    GOTOOLCHAIN=local \
    CGO_ENABLED=1 \
    CC=clang-20 \
    CXX=clang++-20
