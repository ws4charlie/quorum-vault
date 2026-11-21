#!/usr/bin/env bash
# The live dashboard of a load run: Prometheus and Grafana in Docker (deploy/load/compose.yml). `up` starts them and prints the address, `down` removes them.
# The load test (make load-local) writes its scrape targets into data/load/targets, which Prometheus watches: start this first, then run the test.
set -euo pipefail
cd "$(dirname "$0")/../.."
. scripts/e2e-lane.sh # this checkout's lane (compose project name and ports)
proj="qvload-$(lane_project | sed 's/^qve2e-//')"
base="$(lane_port_base)"
export QV_LOAD_TARGETS_DIR="$PWD/data/load/targets"
export QV_LOAD_PROM_PORT="${QV_LOAD_PROM_PORT:-$((base + 87))}"
export QV_LOAD_GRAFANA_PORT="${QV_LOAD_GRAFANA_PORT:-$((base + 86))}"
case "${1:-}" in
  up)
    mkdir -p "$QV_LOAD_TARGETS_DIR"
    docker compose -p "$proj" -f deploy/load/compose.yml up -d --wait
    echo "Grafana:    http://127.0.0.1:$QV_LOAD_GRAFANA_PORT  (dashboard: QuorumVault load run)"
    echo "Prometheus: http://127.0.0.1:$QV_LOAD_PROM_PORT"
    ;;
  down)
    docker compose -p "$proj" -f deploy/load/compose.yml down -v
    ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
