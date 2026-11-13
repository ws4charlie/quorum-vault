#!/usr/bin/env bash
# Runs every CI test group at the same time on this machine, each in an isolated lane, and reports one line per group.
#   make test-e2e-all                          all groups
#   make test-e2e-all GROUPS=e2e-btc-cold,test   a subset (CI job names; "evm", "btc" and "sol" stand for all their groups)
#   make test-e2e-all LANES=4                  another number of lanes (default 6)
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
# services: p postgres, a anvil, b bitcoind, s solana-test-validator, i Temporal and Redpanda. Ordered by weight, heaviest first.
GROUP_TABLE="
e2e-evm-flows|pai|351|3|make test-e2e-evm-flows
e2e-btc-recovery|pbi|345|3|make test-e2e-btc-recovery
e2e-btc-sweeps|pbi|287|3|make test-e2e-btc-sweeps
e2e-btc-refill-stuck|pbi|262|3|make test-e2e-btc-refill-stuck
e2e-evm-recovery|pai|212|3|make test-e2e-evm-recovery
e2e-btc-consolidate|pbi|201|3|make test-e2e-btc-consolidate
e2e-btc-cold|pbi|197|3|make test-e2e-btc-cold
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
test|p|90|1|go vet ./... && QV_REQUIRE_DB=1 QV_REQUIRE_HSM=1 go test -short -count=1 -p 1 ./...
mpc-signing|pa|74|1|make test-mpc
"
ALL_GROUPS="$(printf '%s\n' "$GROUP_TABLE" | sed -n 's/^\([^|]*\)|.*/\1/p' | tr '\n' ' ')"

LANES="${LANES:-6}"
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
i=1; while [ "$i" -le "$LANES" ]; do load[$i]=0; lane_groups[$i]=""; lane_svc[$i]="p"; i=$((i + 1)); done
for g in $selected; do
  best=1; i=2
  while [ "$i" -le "$LANES" ]; do [ "${load[$i]}" -lt "${load[$best]}" ] && best=$i; i=$((i + 1)); done
  # A group that needs the Solana validator goes to a lane that already has one: the validator is the heaviest container (an x86_64 binary,
  # emulated on Apple silicon), so a run starts as few as it can.
  case "$(field "$g" 2)" in *s*)
    sbest=""; i=1
    while [ "$i" -le "$LANES" ]; do
      case "${lane_svc[$i]}" in *s*) if [ -z "$sbest" ] || [ "${load[$i]}" -lt "${load[$sbest]}" ]; then sbest=$i; fi ;; esac
      i=$((i + 1))
    done
    [ -n "$sbest" ] && best=$sbest ;;
  esac
  load[$best]=$((${load[$best]} + $(field "$g" 3)))
  lane_groups[$best]="${lane_groups[$best]} $g"
  svc="$(field "$g" 2)"
  case "$svc" in *a*) case "${lane_svc[$best]}" in *a*) ;; *) lane_svc[$best]="${lane_svc[$best]}a" ;; esac ;; esac
  case "$svc" in *b*) case "${lane_svc[$best]}" in *b*) ;; *) lane_svc[$best]="${lane_svc[$best]}b" ;; esac ;; esac
  case "$svc" in *s*) case "${lane_svc[$best]}" in *s*) ;; *) lane_svc[$best]="${lane_svc[$best]}s" ;; esac ;; esac
  case "$svc" in *i*) NEED_INFRA=1 ;; esac
done
NEED_INFRA="${NEED_INFRA:-0}"

# ports: shared Temporal and Redpanda, then ten per lane (Postgres, anvil, bitcoind, solana)
T_PORT=$((BASE + 1)); K_PORT=$((BASE + 2))
pg_port() { echo $((BASE + 10 * $1)); }
anvil_port() { echo $((BASE + 10 * $1 + 1)); }
btc_port() { echo $((BASE + 10 * $1 + 2)); }
sol_port() { echo $((BASE + 10 * $1 + 3)); }

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
check_ports() {
  local busy="" p i
  [ "$NEED_INFRA" = 1 ] && for p in $T_PORT $K_PORT; do port_busy "$p" && busy="$busy $p"; done
  i=1; while [ "$i" -le "$LANES" ]; do
    for p in $(pg_port $i) $(anvil_port $i) $(btc_port $i) $(sol_port $i); do port_busy "$p" && busy="$busy $p"; done
    i=$((i + 1))
  done
  [ -z "$busy" ] || die "ports in use:$busy (another make test-e2e-all running? set QV_E2E_PORT_BASE to move the range)"
}

# ---- compose ----
dc() { # dc <project> <args...>: docker compose with the ports of that project in the environment
  local project=$1; shift
  case "$project" in
    "$PROJ-shared") COMPOSE_PROJECT_NAME="$project" QV_TEMPORAL_PORT=$T_PORT QV_KAFKA_PORT=$K_PORT docker compose "$@" ;;
    *) local n=${project##*-l}
       COMPOSE_PROJECT_NAME="$project" QV_PG_PORT=$(pg_port "$n") QV_ANVIL_PORT=$(anvil_port "$n") QV_BTC_PORT=$(btc_port "$n") QV_SOL_PORT=$(sol_port "$n") docker compose "$@" ;;
  esac
}

down_all() {
  local i=1 pids="" p
  ( dc "$PROJ-shared" --profile infra down -v --remove-orphans >/dev/null 2>&1 ) & pids="$pids $!"
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
check_ports
started=1
say "e2e-all: $ngroups groups on $LANES lanes; logs and results in $OUT"
i=1; while [ "$i" -le "$LANES" ]; do say "  lane $i (~${load[$i]}s in CI):${lane_groups[$i]}  [services: ${lane_svc[$i]}]"; i=$((i + 1)); done

# ---- start: clean slate, then shared services and every lane at the same time ----
t0=$SECONDS
down_all
# The validator image is built once here (Docker's layer cache makes a repeat instant), not once per lane: the lanes then start containers from it.
i=1; while [ "$i" -le "$LANES" ]; do
  case "${lane_svc[$i]}" in *s*) docker compose --profile solana build solana >"$OUT/solana-build.log" 2>&1 || die "building the Solana validator image failed (see $OUT/solana-build.log)"; break ;; esac
  i=$((i + 1))
done
start_lane() { # start_lane <n>: Postgres, the chains it needs, and the lane's SoftHSM tokens
  local n=$1 svcs="postgres" prof=()
  case "${lane_svc[$n]}" in *a*) svcs="$svcs anvil" ;; esac
  case "${lane_svc[$n]}" in *b*) svcs="$svcs bitcoind"; prof=(--profile btc) ;; esac
  case "${lane_svc[$n]}" in *s*) svcs="$svcs solana"; prof+=(--profile solana) ;; esac
  mkdir -p "$OUT/lane$n"
  ( QV_SOFTHSM_DIR="$OUT/lane$n/softhsm" ./scripts/setup-softhsm.sh >"$OUT/lane$n/softhsm-setup.log" 2>&1 ) || return 1
  dc "$PROJ-l$n" ${prof[@]+"${prof[@]}"} up -d --wait $svcs >"$OUT/lane$n/up.log" 2>&1
}
pids=""; names=""
if [ "$NEED_INFRA" = 1 ]; then
  ( dc "$PROJ-shared" --profile infra up -d --wait temporal-db temporal redpanda >"$OUT/shared-up.log" 2>&1 ) & pids="$pids $!"; names="$names shared"
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
    export DATABASE_URL="postgres://qv@localhost:$(pg_port "$n")/quorumvault?sslmode=disable"
    export QV_ANVIL_RPC="http://127.0.0.1:$(anvil_port "$n")" QV_BTC_RPC="http://127.0.0.1:$(btc_port "$n")" QV_SOL_RPC="http://127.0.0.1:$(sol_port "$n")"
    export QV_TEMPORAL_ADDR="127.0.0.1:$T_PORT" QV_KAFKA_BROKERS="127.0.0.1:$K_PORT"
    export SOFTHSM2_CONF="$OUT/lane$n/softhsm/softhsm2.conf"
    export COMPOSE_PROJECT_NAME="$PROJ-l$n" QV_PG_PORT=$(pg_port "$n") QV_ANVIL_PORT=$(anvil_port "$n") QV_BTC_PORT=$(btc_port "$n") QV_SOL_PORT=$(sol_port "$n")
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
