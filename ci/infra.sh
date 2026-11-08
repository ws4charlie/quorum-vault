#!/usr/bin/env bash
# The services a CI job's tests talk to, started in the background so the job can do its other set-up meanwhile, and waited for right before the tests.
#   ci/infra.sh start [--anvil] [--infra] [--bitcoind]   returns at once
#   ci/infra.sh wait                                      blocks until everything started is ready (5 minutes at most); logs on failure
#     --anvil     anvil, chain id 11155111, on 127.0.0.1:18545 (EVM jobs and the signing job)
#     --infra     Temporal and Redpanda (docker compose profile infra)
#     --bitcoind  bitcoind in regtest on 127.0.0.1:18443 (docker compose profile btc)
# Run from the checkout, on the host (compose reads docker-compose.yml). State is in $QV_INFRA_DIR (default $RUNNER_TEMP/qv-infra).
set -uo pipefail
cd "$(dirname "$0")/.."
DIR="${QV_INFRA_DIR:-${RUNNER_TEMP:-/tmp}/qv-infra}"
FOUNDRY=ghcr.io/foundry-rs/foundry:v1.8.5

bg() { # bg <name> <command...>: runs in the background; <name>.status holds the exit code when it is over
  local name=$1; shift
  ( "$@" >"$DIR/$name.log" 2>&1; echo $? >"$DIR/$name.status" ) </dev/null &
  disown
}

start_anvil() {
  docker run -d --name anvil -p 127.0.0.1:18545:8545 "$FOUNDRY" "anvil --host 0.0.0.0 --chain-id 11155111" || return 1
  for _ in $(seq 1 60); do
    curl -sf -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' http://127.0.0.1:18545 && { echo; return 0; }
    sleep 1
  done
  docker logs anvil
  return 1
}

case "${1:-}" in
start)
  shift
  rm -rf "$DIR"; mkdir -p "$DIR"
  anvil=0; services=(); profiles=()
  for a in "$@"; do
    case "$a" in
      --anvil) anvil=1 ;;
      --infra) profiles+=(--profile infra); services+=(temporal-db temporal redpanda) ;;
      --bitcoind) profiles+=(--profile btc); services+=(bitcoind) ;;
      *) echo "unknown flag $a" >&2; exit 2 ;;
    esac
  done
  [ "$anvil" = 1 ] && bg anvil start_anvil
  # One compose command for everything it starts: two at once would race to create the project's network.
  [ "${#services[@]}" -gt 0 ] && bg compose docker compose "${profiles[@]}" up -d --wait "${services[@]}"
  echo "started in the background; logs in $DIR"
  ;;
wait)
  deadline=$((SECONDS + 300))
  failed=0
  for name in anvil compose; do
    [ -e "$DIR/$name.log" ] || continue
    while [ ! -e "$DIR/$name.status" ]; do
      if [ "$SECONDS" -gt "$deadline" ]; then echo "timed out waiting for $name"; failed=1; break; fi
      sleep 0.5
    done
    rc="$(cat "$DIR/$name.status" 2>/dev/null || echo timeout)"
    echo "---- $name: exit $rc ----"
    if [ "$rc" != 0 ]; then failed=1; cat "$DIR/$name.log"; fi
  done
  if [ "$failed" != 0 ]; then
    docker ps -a || true
    docker compose --profile infra --profile btc logs --tail 80 || true
    exit 1
  fi
  echo "services are ready"
  ;;
*)
  echo "usage: $0 start [--anvil] [--infra] [--bitcoind] | wait" >&2
  exit 2
  ;;
esac
