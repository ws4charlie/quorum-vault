#!/usr/bin/env bash
# Runs every CI test group at the same time on this machine, each in an isolated lane, and reports one line per group.
#   make test-e2e-all                          all groups
#   make test-e2e-all GROUPS=e2e-btc-cold,test   a subset (CI job names; "evm", "btc" and "sol" stand for all their groups)
#   make test-e2e-all LANES=4                  another number of lanes (default 8)
#
# A lane is the set of services that tests change: its own Postgres (the tests create and drop databases and switch a role's LOGIN),
# its own anvil and/or bitcoind (tests mine, reorg, restart and fund), and its own SoftHSM token store. Temporal and Redpanda are one
# shared pair: the tests name their task queues, databases and audit sources with random suffixes. A lane runs its groups one after
# another; lanes run at the same time. Nothing the single targets use is touched: every port is in a separate range
# (QV_E2E_PORT_BASE, default 41000), every container is in a compose project named qve2e-*, and the Makefile targets run as they are.
#
# Needs what the single targets need: `make softhsm mpc-build`, Docker, softhsm2-util, Go. Logs: data/e2e-all/<time>/<group>.log.
# Exit code: 0 only if every group passed. Ctrl-C stops the groups and removes every container it started.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

# name|services|weight (seconds in a CI run, for balancing)|QV_E2E_TIMEOUT_SCALE (CI's value)|command
# services: p postgres, a anvil, b bitcoind, s solana-test-validator, i Temporal and Redpanda, k Keycloak (one, shared like Temporal). Ordered by weight, heaviest first.
GROUP_TABLE="
e2e-evm-flows|pai|351|3|make test-e2e-evm-flows
e2e-btc-recovery|pbi|345|3|make test-e2e-btc-recovery
e2e-btc-sweeps|pbi|287|3|make test-e2e-btc-sweeps
e2e-btc-refill-stuck|pbi|262|3|make test-e2e-btc-refill-stuck
e2e-evm-recovery|pai|212|3|make test-e2e-evm-recovery
e2e-btc-consolidate|pbi|201|3|make test-e2e-btc-consolidate
e2e-btc-batching|pbi|140|3|make test-e2e-btc-batching
e2e-btc-batching-recovery|pbi|155|3|make test-e2e-btc-batching-recovery
e2e-btc-cpfp|pbi|220|3|make test-e2e-btc-cpfp
e2e-btc-cold|pbi|197|3|make test-e2e-btc-cold
e2e-btc-feecaps|pbi|200|3|make test-e2e-btc-feecaps
e2e-btc-refill|pbi|190|3|make test-e2e-btc-refill
e2e-btc-withdrawals|pbi|153|3|make test-e2e-btc-withdrawals
e2e-evm-tx-failures|pai|148|3|make test-e2e-evm-tx-failures
e2e-btc-deposits|pbi|96|3|make test-e2e-btc-deposits
e2e-sol-deposits|psi|150|3|make test-e2e-sol-deposits
e2e-sol-signing|ps|60|3|make test-e2e-sol-signing
e2e-sol-withdrawals|psi|130|3|make test-e2e-sol-withdrawals
e2e-sol-wd-faults|psi|300|3|make test-e2e-sol-wd-faults
e2e-sol-sweeps|psi|140|3|make test-e2e-sol-sweeps
e2e-sol-sweep-faults|psi|290|3|make test-e2e-sol-sweep-faults
e2e-sol-cold|psi|300|3|make test-e2e-sol-cold
e2e-sol-cold-crash|psi|150|3|make test-e2e-sol-cold-crash
e2e-sol-cold-moves-crash|psi|150|3|make test-e2e-sol-cold-moves-crash
e2e-sol-nonces|psi|90|3|make test-e2e-sol-nonces
e2e-evm-identity|paik|100|3|make test-e2e-evm-identity
e2e-approval-web|paik|60|3|make test-e2e-approval-web
test|p|90|1|go vet ./... && QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 go test -short -count=1 -p 1 ./...
mpc-signing|pa|74|1|make test-mpc
"
# heaviest first, whatever the table's order
ALL_GROUPS="$(printf '%s\n' "$GROUP_TABLE" | grep '|' | sort -t'|' -k3,3 -rn | cut -d'|' -f1 | tr '\n' ' ')"

LANES="${LANES:-8}"
BASE="${QV_E2E_PORT_BASE:-41000}"
PROJ="qve2e"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${QV_E2E_OUT:-$ROOT/data/e2e-all/$STAMP}"

say() { printf '%s\n' "$*"; }
die() { printf 'e2e-all: %s\n' "$*" >&2; exit 2; }

# ---- which groups ----
selected=""
want="${QV_E2E_GROUPS:-}"
if [ -z "$want" ]; then
  selected="$ALL_GROUPS"
else
  for g in $(printf '%s' "$want" | tr ',' ' '); do
    case "$g" in
      evm) add="$(printf '%s ' $ALL_GROUPS | tr ' ' '\n' | grep '^e2e-evm-' | tr '\n' ' ')" ;;
      btc) add="$(printf '%s ' $ALL_GROUPS | tr ' ' '\n' | grep '^e2e-btc-' | tr '\n' ' ')" ;;
      sol) add="$(printf '%s ' $ALL_GROUPS | tr ' ' '\n' | grep '^e2e-sol-' | tr '\n' ' ')" ;;
      *)   add="$g" ;;
    esac
    for a in $add; do
      case " $ALL_GROUPS " in *" $a "*) ;; *) die "unknown group '$a'; groups: $ALL_GROUPS" ;; esac
      case " $selected " in *" $a "*) ;; *) selected="$selected $a" ;; esac
    done
  done
fi
# keep the table's order (heaviest first) whatever order the caller named them in
ordered=""
for g in $ALL_GROUPS; do case " $selected " in *" $g "*) ordered="$ordered $g" ;; esac; done
selected="$ordered"
[ -n "$selected" ] || die "no groups selected"

field() { # field <group> <n>: the n-th |-separated field of the group's table line
  printf '%s\n' "$GROUP_TABLE" | grep "^$1|" | head -n1 | cut -d'|' -f"$2"
}
ngroups=$(printf '%s\n' $selected | wc -l | tr -d ' ')
[ "$LANES" -gt "$ngroups" ] && LANES="$ngroups"
[ "$LANES" -ge 1 ] || die "LANES must be at least 1"

# ---- lanes: heaviest group first, each to the lane with the least weight so far ----
# The Solana validator is the heaviest container (an x86_64 binary, emulated on Apple silicon: ~1.3 GB and over one core each), so only the first
# SOL_LANES lanes run one, and the Solana groups are spread over those lanes by weight (default: one validator per ~600 s of CI time, at most 3).
sol_weight=0
for g in $selected; do case "$(field "$g" 2)" in *s*) sol_weight=$((sol_weight + $(field "$g" 3))) ;; esac; done
# How many validators fit: memory the Docker VM has free now (other stacks on this machine count), since the kernel kills the biggest container
# when the VM runs out (seen: a validator "exited 137, OOMKilled", the group then failing with "sol rpc getSlot: EOF"). Measured per validator
# ~1.6 GB in its cgroup plus emulation overhead outside it, so 1.8 GB is reserved; ~250 MB per lane; ~0.7 GB for Temporal and Redpanda.
vm_free_mb=0
if [ "$sol_weight" -gt 0 ] && [ -z "${QV_E2E_SOL_LANES:-}" ] && command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  vm_free_mb=$(docker run --rm --pid=host alpine awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
fi
SOL_LANES="${QV_E2E_SOL_LANES:-$(( (sol_weight + 599) / 600 ))}"
[ "$SOL_LANES" -gt 3 ] && SOL_LANES=3
if [ -z "${QV_E2E_SOL_LANES:-}" ] && [ "${vm_free_mb:-0}" -gt 0 ]; then
  fit=$(( (vm_free_mb - 700 - 250 * LANES) / 1800 ))
  [ "$fit" -lt 1 ] && fit=1
  [ "$SOL_LANES" -gt "$fit" ] && SOL_LANES=$fit
  SOL_NOTE="Docker VM has ${vm_free_mb} MB free: $SOL_LANES Solana validator(s)"
fi
# Fewer than one validator's worth is not a run that "mostly works": every run that started below this lost a validator to the OOM killer
# or Temporal to a stall ("register namespace: context deadline exceeded") some minutes in. Say so now instead.
if [ "${vm_free_mb:-0}" -gt 0 ] && [ "${QV_E2E_FORCE:-0}" != 1 ]; then
  need_mb=$(( 700 + 250 * LANES + 2300 * SOL_LANES + 1000 ))
  if [ "$vm_free_mb" -lt "$need_mb" ]; then
    die "the Docker VM has ${vm_free_mb} MB free and this run needs about ${need_mb} MB (Temporal and Redpanda, ${LANES} lanes, ${SOL_LANES} Solana validator(s) of ~1.6 GB that grow while they run): stop other compose stacks (docker ps), or give Docker Desktop more memory (Settings > Resources), or run fewer groups (QV_E2E_GROUPS=evm,btc,test) or LANES=3. QV_E2E_FORCE=1 runs anyway (expect random failures)."
  fi
fi
[ "$SOL_LANES" -gt "$LANES" ] && SOL_LANES=$LANES
[ "$sol_weight" -gt 0 ] && [ "$SOL_LANES" -lt 1 ] && SOL_LANES=1
i=1; while [ "$i" -le "$LANES" ]; do load[$i]=0; lane_groups[$i]=""; lane_svc[$i]="p"; i=$((i + 1)); done
# the Solana groups first (they can only go to the validator lanes), then the others fill whatever is lightest
sorted_groups=""
for g in $selected; do case "$(field "$g" 2)" in *s*) sorted_groups="$sorted_groups $g" ;; esac; done
for g in $selected; do case "$(field "$g" 2)" in *s*) ;; *) sorted_groups="$sorted_groups $g" ;; esac; done
for g in $sorted_groups; do
  svc="$(field "$g" 2)"
  limit=$LANES
  case "$svc" in *s*) limit=$SOL_LANES ;; esac
  best=1; i=2
  while [ "$i" -le "$limit" ]; do [ "${load[$i]}" -lt "${load[$best]}" ] && best=$i; i=$((i + 1)); done
  load[$best]=$((${load[$best]} + $(field "$g" 3)))
  lane_groups[$best]="${lane_groups[$best]} $g"
  case "$svc" in *a*) case "${lane_svc[$best]}" in *a*) ;; *) lane_svc[$best]="${lane_svc[$best]}a" ;; esac ;; esac
  case "$svc" in *b*) case "${lane_svc[$best]}" in *b*) ;; *) lane_svc[$best]="${lane_svc[$best]}b" ;; esac ;; esac
  case "$svc" in *s*) case "${lane_svc[$best]}" in *s*) ;; *) lane_svc[$best]="${lane_svc[$best]}s" ;; esac ;; esac
  case "$svc" in *i*) NEED_INFRA=1 ;; esac
  case "$svc" in *k*) NEED_KC=1 ;; esac
done
NEED_INFRA="${NEED_INFRA:-0}"
NEED_KC="${NEED_KC:-0}"

# ports: shared Temporal and Redpanda, then ten per lane (Postgres, anvil, bitcoind, solana, signing-zone Postgres)
T_PORT=$((BASE + 1)); K_PORT=$((BASE + 2)); KC_PORT=$((BASE + 3))
pg_port() { echo $((BASE + 10 * $1)); }
anvil_port() { echo $((BASE + 10 * $1 + 1)); }
btc_port() { echo $((BASE + 10 * $1 + 2)); }
sol_port() { echo $((BASE + 10 * $1 + 3)); }
sdb_port() { echo $((BASE + 10 * $1 + 4)); }

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
check_ports() {
  local busy="" p i
  [ "$NEED_INFRA" = 1 ] && for p in $T_PORT $K_PORT; do port_busy "$p" && busy="$busy $p"; done
  [ "$NEED_KC" = 1 ] && { port_busy "$KC_PORT" && busy="$busy $KC_PORT"; }
  i=1; while [ "$i" -le "$LANES" ]; do
    for p in $(pg_port $i) $(anvil_port $i) $(btc_port $i) $(sol_port $i) $(sdb_port $i); do port_busy "$p" && busy="$busy $p"; done
    i=$((i + 1))
  done
  [ -z "$busy" ] || die "ports in use:$busy (another make test-e2e-all running? set QV_E2E_PORT_BASE to move the range)"
}

# ---- compose ----
dc() { # dc <project> <args...>: docker compose with the ports of that project in the environment
  local project=$1; shift
  case "$project" in
    "$PROJ-shared") COMPOSE_PROJECT_NAME="$project" QV_TEMPORAL_PORT=$T_PORT QV_KAFKA_PORT=$K_PORT QV_KEYCLOAK_PORT=$KC_PORT docker compose "$@" ;;
    *) local n=${project##*-l}
       COMPOSE_PROJECT_NAME="$project" QV_PG_PORT=$(pg_port "$n") QV_SIGNING_DB_PORT=$(sdb_port "$n") QV_ANVIL_PORT=$(anvil_port "$n") QV_BTC_PORT=$(btc_port "$n") QV_SOL_PORT=$(sol_port "$n") docker compose "$@" ;;
  esac
}

down_all() {
  local i=1 pids="" p
  ( dc "$PROJ-shared" --profile infra --profile identity down -v --remove-orphans >/dev/null 2>&1 ) & pids="$pids $!"
  while [ "$i" -le "$LANES" ]; do
    ( dc "$PROJ-l$i" --profile btc --profile solana down -v --remove-orphans >/dev/null 2>&1 ) & pids="$pids $!"
    i=$((i + 1))
  done
  for p in $pids; do wait "$p" 2>/dev/null; done
}

lane_pids=""
cleaned=0
started=0 # set once the ports are known free: before that, a cleanup would stop the containers of another run
cleanup() {
  [ "$cleaned" = 1 ] && return
  cleaned=1
  [ "$started" = 1 ] || return
  trap '' INT TERM
  local p
  if [ -n "$lane_pids" ]; then
    for p in $lane_pids; do kill -TERM -- "-$p" 2>/dev/null; done
    sleep 2
    for p in $lane_pids; do kill -KILL -- "-$p" 2>/dev/null; done
  fi
  for p in $(jobs -p); do kill -TERM -- "-$p" 2>/dev/null; done
  say "stopping the services this run started..."
  down_all
}
trap 'cleanup; exit 130' INT TERM
trap 'cleanup' EXIT
set -m # each lane in its own process group, so one kill reaches the group's go test, make and children

# ---- go ----
for t in docker go softhsm2-util; do command -v "$t" >/dev/null || die "$t not found"; done
docker info >/dev/null 2>&1 || die "docker is not running"
. "$ROOT/scripts/lib-pins.sh"
qv_load_pins --so || die "no SoftHSM PINs"
[ -d mpc-party/.deps ] || die "cb-mpc is not built: run make mpc-build first"
mkdir -p "$OUT"
# Fresh certificate authorities (one per trust zone) and short-lived certificates for this run; every group's processes and the Postgres servers use them.
export QV_PKI_DIR="$OUT/pki"
./scripts/pki.sh >"$OUT/pki.log" 2>&1 || die "making the TLS certificates failed (see $OUT/pki.log)"
check_ports
started=1
say "e2e-all: $ngroups groups on $LANES lanes; logs and results in $OUT"
[ -n "${SOL_NOTE:-}" ] && say "  ($SOL_NOTE; QV_E2E_SOL_LANES=n sets it, and more validators need more Docker memory)"
i=1; while [ "$i" -le "$LANES" ]; do say "  lane $i (~${load[$i]}s in CI):${lane_groups[$i]}  [services: ${lane_svc[$i]}]"; i=$((i + 1)); done
[ "${QV_E2E_PLAN_ONLY:-0}" = 1 ] && exit 0 # print the lanes and stop (cleanup has nothing to stop: nothing was started)

# ---- start: clean slate, then shared services and every lane at the same time ----
t0=$SECONDS
down_all
# The validator image is built once here (Docker's layer cache makes a repeat instant), not once per lane: the lanes then start containers from it.
i=1; while [ "$i" -le "$LANES" ]; do
  case "${lane_svc[$i]}" in *s*) docker compose --profile solana build solana >"$OUT/solana-build.log" 2>&1 || die "building the Solana validator image failed (see $OUT/solana-build.log)"; break ;; esac
  i=$((i + 1))
done
start_lane() { # start_lane <n>: Postgres, the chains it needs, and the lane's SoftHSM tokens
  local n=$1 svcs="postgres signing-db" prof=()
  case "${lane_svc[$n]}" in *a*) svcs="$svcs anvil" ;; esac
  case "${lane_svc[$n]}" in *b*) svcs="$svcs bitcoind"; prof=(--profile btc) ;; esac
  case "${lane_svc[$n]}" in *s*) svcs="$svcs solana"; prof+=(--profile solana) ;; esac
  mkdir -p "$OUT/lane$n"
  ( QV_SOFTHSM_DIR="$OUT/lane$n/softhsm" ./scripts/setup-softhsm.sh >"$OUT/lane$n/softhsm-setup.log" 2>&1 ) || return 1
  dc "$PROJ-l$n" ${prof[@]+"${prof[@]}"} up -d --wait $svcs >"$OUT/lane$n/up.log" 2>&1
}
pids=""; names=""
if [ "$NEED_INFRA" = 1 ]; then
  ( dc "$PROJ-shared" --profile infra up -d --wait temporal-db temporal temporal-gate redpanda >"$OUT/shared-up.log" 2>&1 ) & pids="$pids $!"; names="$names shared"
fi
if [ "$NEED_KC" = 1 ]; then
  ./scripts/keycloak-env.sh >/dev/null
  ( dc "$PROJ-shared" --profile identity up -d --wait keycloak >"$OUT/keycloak-up.log" 2>&1 ) & pids="$pids $!"; names="$names keycloak"
fi
i=1; while [ "$i" -le "$LANES" ]; do
  start_lane $i & pids="$pids $!"; names="$names lane$i"
  i=$((i + 1))
done
# warm the Go caches once (the e2e test binaries build the qv-* and mpc-party binaries in TestMain), so the lanes do not all compile at once
( QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 QV_REQUIRE_CUSTODY=1 QV_REQUIRE_BTC=1 QV_CUSTODY_SIGNER=mpc QV_MPC_E2E=1 \
    go test -count=1 -run '^$' ./e2e/custody/ ./e2e/btc/ ./e2e/sol/ ./e2e/solsign/ ./e2e/mpcsign/ >"$OUT/warm-build.log" 2>&1 ) & pids="$pids $!"; names="$names go-build"
failed=""
set -- $names
for p in $pids; do wait "$p" || failed="$failed $1"; shift; done
if [ -n "$failed" ]; then
  say "e2e-all: set-up failed for:$failed (see the *.log files in $OUT and $OUT/lane*/)"
  exit 3
fi
say "e2e-all: services ready after $((SECONDS - t0))s"

# ---- run ----
run_group() { # run_group <lane> <group>
  local n=$1 g=$2 cmd scale t1 rc
  cmd="$(field "$g" 5)"; scale="$(field "$g" 4)"
  t1=$SECONDS
  say "  start  $g (lane $n)"
  (
    export DATABASE_URL="postgres://qv@localhost:$(pg_port "$n")/quorumvault?sslmode=verify-full&sslrootcert=$OUT/pki/business/admin/ca.crt&sslcert=$OUT/pki/business/admin/tls.crt&sslkey=$OUT/pki/business/admin/tls.key"
    export QV_SIGNING_DB_URL="postgres://qv@localhost:$(sdb_port "$n")/qv_signing?sslmode=verify-full&sslrootcert=$OUT/pki/signing/admin/ca.crt&sslcert=$OUT/pki/signing/admin/tls.crt&sslkey=$OUT/pki/signing/admin/tls.key"
    export QV_ANVIL_RPC="http://127.0.0.1:$(anvil_port "$n")" QV_BTC_RPC="http://127.0.0.1:$(btc_port "$n")" QV_SOL_RPC="http://127.0.0.1:$(sol_port "$n")"
    export QV_PKI_DIR="$OUT/pki"
    export QV_TEMPORAL_ADDR="127.0.0.1:$T_PORT" QV_KAFKA_BROKERS="127.0.0.1:$K_PORT"
    export SOFTHSM2_CONF="$OUT/lane$n/softhsm/softhsm2.conf"
    export COMPOSE_PROJECT_NAME="$PROJ-l$n" QV_PG_PORT=$(pg_port "$n") QV_ANVIL_PORT=$(anvil_port "$n") QV_BTC_PORT=$(btc_port "$n") QV_SOL_PORT=$(sol_port "$n")
    case "$(field "$g" 2)" in *k*) export QV_E2E_KEYCLOAK_URL="https://127.0.0.1:$KC_PORT" ;; esac
    [ "$scale" -gt 1 ] && export QV_E2E_TIMEOUT_SCALE="${QV_E2E_TIMEOUT_SCALE:-$scale}"
    exec bash -c "$cmd"
  ) >"$OUT/$g.log" 2>&1 </dev/null
  rc=$?
  printf '%s\t%s\t%s\t%s\n' "$g" "$rc" "$((SECONDS - t1))" "$n" >>"$OUT/results.tsv"
  if [ "$rc" = 0 ]; then
    printf '  PASS   %-22s %4ds  lane %s  %s\n' "$g" "$((SECONDS - t1))" "$n" "$OUT/$g.log"
  else
    printf '  FAIL   %-22s %4ds  lane %s  %s  (exit %s)\n' "$g" "$((SECONDS - t1))" "$n" "$OUT/$g.log" "$rc"
  fi
}
: >"$OUT/results.tsv"
t1=$SECONDS
i=1; while [ "$i" -le "$LANES" ]; do
  ( for g in ${lane_groups[$i]}; do run_group "$i" "$g"; done ) & lane_pids="$lane_pids $!"
  i=$((i + 1))
done
for p in $lane_pids; do wait "$p"; done
lane_pids=""

# ---- summary ----
npass=$(awk -F'\t' '$2==0' "$OUT/results.tsv" | wc -l | tr -d ' ')
nfail=$(awk -F'\t' '$2!=0' "$OUT/results.tsv" | wc -l | tr -d ' ')
say ""
say "e2e-all: $npass passed, $nfail failed of $ngroups groups; tests ran $((SECONDS - t1))s, whole run $((SECONDS - t0))s"
if [ "$nfail" != 0 ] || [ "$((npass + nfail))" != "$ngroups" ]; then
  awk -F'\t' -v d="$OUT" '$2!=0 {print "  FAILED " $1 "  log: " d "/" $1 ".log"}' "$OUT/results.tsv"
  exit 1
fi
exit 0
