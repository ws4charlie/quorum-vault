# Shared by the withdrawal and crash cases: port-forwards to core, Keycloak, anvil and bitcoind, the kindwd driver, and the switch between the EVM and the Bitcoin custody config.
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
cd "$QV_KIND_ROOT"
S="$WORK/secrets"; C="$WORK/cfg"
PF_PIDS=()
fwd() { # var ns target port: starts a port-forward and puts its local port in $var
  pf_start "$2" "$3" "$4"; PF_PIDS+=("$PF_PID"); printf -v "$1" %s "$PF_PORT"
}
wd_down() { local p; for p in "${PF_PIDS[@]:-}"; do if [ -n "$p" ]; then kill "$p" 2> /dev/null || true; fi; done; PF_PIDS=(); return 0; }
wd_up() {
  fwd P_CORE "$NS_BIZ" svc/qv-business-core 8443; fwd P_KC "$NS_BIZ" svc/keycloak 8443
  fwd P_ANVIL "$NS_BIZ" svc/anvil 8545; fwd P_BTC "$NS_BIZ" svc/bitcoind 18443
}
wd() { go run ./ci/kind/tools/kindwd -core "127.0.0.1:$P_CORE" -kc "127.0.0.1:$P_KC" -ca "$S/ca-business.crt" -secrets "$S" -rpc "http://127.0.0.1:$P_ANVIL" -btc "http://127.0.0.1:$P_BTC" "$@"; }
# which chain the business pods serve: the custody config is a Secret, so a switch is a new Secret and a restart of the pods that read it
use_custody() { # evm|btc: the forwards to the old pods are closed first and made again to the new ones
  wd_down
  kn "$NS_BIZ" create secret generic qv-custody-config --from-file=config.json="$C/custody-$1.json" --dry-run=client -o yaml | k apply -f - > /dev/null
  kn "$NS_BIZ" rollout restart deploy/qv-business-core deploy/qv-business-worker deploy/qv-business-relay > /dev/null
  local d; for d in core worker relay; do kn "$NS_BIZ" rollout status deploy/qv-business-$d --timeout=180s > /dev/null; done
  wd_up
}
