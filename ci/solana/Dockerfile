# solana-test-validator for the Solana end-to-end tests: a local single-node cluster with a fresh ledger on every start.
#
# Pinned: Agave v3.0.14 (anza-xyz/agave release, the last patch of the 3.0 line), the Linux x86_64 release tarball, checked against its
# published sha256. Why not the newer v4.x: v4 asserts at start that the kernel offers io_uring (agave fs/src/dirs.rs). That fails where
# the x86_64 binary is emulated (Docker Desktop on Apple silicon: the syscall is not implemented), and Docker's default seccomp profile
# blocks io_uring on a Linux host unless the container is run unconfined. v3.0.14 starts everywhere the tests run. Revisit when v4 is
# wanted (a newer pin needs a runner that allows io_uring and no emulation). Why a tarball: Anza publishes release binaries for Linux
# x86_64 and macOS only, no maintained validator image, so the image is built from the release with a pinned checksum.
# Base: ubuntu:24.04 pinned by digest, the same as ci/qv-ci.Dockerfile. No key or secret is in any layer: the validator makes its own
# throwaway genesis keys at start.
FROM --platform=linux/amd64 ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
ARG AGAVE_VERSION=v3.0.14
ARG AGAVE_SHA256=65614325423316a48f57f1ceeaa91ca78f4516e165e305b38c01873cf8c6b8b4
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates curl bzip2 libssl3t64 libudev1 >/dev/null \
 && curl -fsSL -o /tmp/agave.tar.bz2 "https://github.com/anza-xyz/agave/releases/download/${AGAVE_VERSION}/solana-release-x86_64-unknown-linux-gnu.tar.bz2" \
 && echo "${AGAVE_SHA256}  /tmp/agave.tar.bz2" | sha256sum -c - \
 && mkdir /opt/agave && tar -xjf /tmp/agave.tar.bz2 -C /opt/agave --strip-components=1 \
 && rm /tmp/agave.tar.bz2 && rm -rf /var/lib/apt/lists/*
ENV PATH=/opt/agave/bin:$PATH
WORKDIR /ledger
EXPOSE 8899 8900
# A fresh ledger every start (--reset). Gossip and the RPC bind to the container's own address (the validator refuses 0.0.0.0); the compose
# file publishes the RPC port on localhost only. A slot is 100 ms (16 ticks), so a transaction is finalized in seconds.
#
# The epoch length is the validator's default (432,000 slots, about twelve hours at 100 ms): a test run never crosses an epoch boundary. An earlier
# version of this file set --slots-per-epoch 32 to keep the cluster small, and that stalled the validator in CI: at full speed (the runner is native
# x86_64; under emulation the slots are slower and it never showed) block production stopped at the last slot of an epoch (slot 159, with finalized
# stuck 32 behind), the validator alive and healthy. Its log then repeated "Couldn't vote on heaviest fork: 63, heaviest_fork_failures:
# [FailedThreshold(63, 4, 0, ..), FailedThreshold(63, 5, 0, ..), FailedThreshold(63, 8, 0, ..)]": the tower's vote threshold check (depth 8) saw no voted
# stake on the fork, so it could not vote, root nothing and, after a few more slots, produce no more. Reproduced locally with --ticks-per-slot 2 and
# 32-slot epochs (stopped at slot 61-63, the end of the second epoch) and not with the default epoch length (12,000 slots in 2.5 minutes at the same
# speed). Do not shorten the epochs again.
ENTRYPOINT ["sh", "-c", "exec solana-test-validator --reset --ledger /ledger --bind-address \"$(hostname -i | cut -d' ' -f1)\" --rpc-port 8899 --ticks-per-slot 16 --limit-ledger-size 100000"]
