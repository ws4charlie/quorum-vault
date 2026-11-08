#!/usr/bin/env bash
# Runs a command in the CI image, in the checkout, as the caller's user, on the host network (so 127.0.0.1 is the runner: Postgres, bitcoind,
# Temporal, Redpanda and anvil are where they are today), with the Docker socket (the tests run `docker compose restart bitcoind`).
# The checkout is mounted at its own path, so compose names its project the same as the host does. The Go module and build caches live in
# $QV_GO_CACHE (default ~/.cache/qv-go) on the host, which the jobs cache between runs. cb-mpc is linked in as mpc-party/.deps.
#   ci/run-in-image.sh make test-e2e-btc-recovery
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
IMAGE="$(ci/image-tag.sh)"
CACHE="${QV_GO_CACHE:-$HOME/.cache/qv-go}"
mkdir -p "$CACHE/mod" "$CACHE/build"
args=(run --rm --network host --user "$(id -u):$(id -g)"
  -v "$ROOT:$ROOT" -w "$ROOT"
  -v "$CACHE:/qv-go" -e GOMODCACHE=/qv-go/mod -e GOCACHE=/qv-go/build
  -e HOME=/tmp/qv-home)
if [ -S /var/run/docker.sock ]; then
  gid="$(stat -c %g /var/run/docker.sock 2>/dev/null || stat -f %g /var/run/docker.sock)"
  args+=(-v /var/run/docker.sock:/var/run/docker.sock --group-add "$gid")
fi
# The job's environment: the variables the Makefile and the tests read.
for v in $(compgen -e | grep -E '^(QV_|DATABASE_URL$|CGO_ENABLED$|CC$|CXX$|COMPOSE_|SOFTHSM2_CONF$)'); do args+=(-e "$v"); done
# cb-mpc comes from the image. A real mpc-party/.deps directory is a host build (macOS objects, or another Linux): it cannot be used in here.
if [ -e mpc-party/.deps ] && [ ! -L mpc-party/.deps ]; then
  echo "run-in-image: mpc-party/.deps is a host build of cb-mpc; move it away: the image has its own (/opt/qv-ci/mpc-party/.deps)" >&2
  exit 1
fi
exec docker "${args[@]}" "$IMAGE" bash -c 'ln -sfn /opt/qv-ci/mpc-party/.deps mpc-party/.deps && exec "$@"' qv-ci "$@"
