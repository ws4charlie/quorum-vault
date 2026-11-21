#!/usr/bin/env bash
# Runs one named end-to-end test many times and prints how many runs passed. The check every new e2e test must pass before review
# (CONTRIBUTING.md: at least 20 runs), and the loop for hunting a flaky one.
#
#   scripts/e2e-repeat.sh [-n 20] <group> <TestRegexp>      a CI group of scripts/e2e-all.sh (e2e-sol-sweeps, mpc-signing, e2e-evm-flows ...)
#   scripts/e2e-repeat.sh [-n 20] core <TestRegexp>         mpc-party's own tests with -race -tags teesim (CI job "mpc-party / core")
#   make e2e-repeat GROUP=mpc-signing TEST=TestLocalRefusalsAndDisagreement N=20
#
# A group run starts the group's services once (scripts/e2e-all.sh, one lane), then runs the group's command N times with -run replaced by
# your regexp, each run a fresh `go test -count=1` (a new test process, a new set of databases and processes; the services are shared by
# the runs, as the tests of one CI job share them). Per run: exit code, seconds, the machine's load average. Logs and the table are
# in data/e2e-repeat/<time>/ (QV_E2E_OUT moves it); the log of a run that did not pass is kept, the log of a pass is dropped (QV_REPEAT_KEEP=1 keeps all).
# A run passes only when go test exits 0, printed at least one "--- PASS" line and no "--- SKIP" line (a regexp that matches nothing, or a test that
# skips itself because something is missing, is not evidence).
# Exit code: 0 only if every run passed. Nothing stops on a failure.
#
# Internal: `scripts/e2e-repeat.sh engine <n> <regexp> <outdir> -- <command...>` is the loop; scripts/e2e-all.sh calls it for QV_E2E_REPEAT.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

die() { printf 'e2e-repeat: %s\n' "$*" >&2; exit 2; }
load1() { sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}' || true; } # macOS; the fallback is below
loadavg() { local l; l="$(load1)"; [ -n "$l" ] || l="$(awk '{print $1}' /proc/loadavg 2>/dev/null)"; printf '%s' "${l:-?}"; }

engine() {
  local n=$1 re=$2 out=$3; shift 3
  [ "$1" = -- ] && shift
  [ "$n" -ge 1 ] 2>/dev/null || die "N must be a number of at least 1"
  mkdir -p "$out"
  # a `go` in front of the real one: every `go test` the command runs gets -v (the count needs the "--- PASS" lines, and the group `test` runs without -v) and
  # -run <regexp> in place of the -run it had
  local shim="$out/shim"; mkdir -p "$shim"
  local real; real="$(command -v go)" || die "go not found"
  cat >"$shim/go" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = test ]; then
  shift; args=()
  while [ \$# -gt 0 ]; do
    case "\$1" in
      -run) shift; [ \$# -gt 0 ] && shift ;;
      -run=*) shift ;;
      *) args+=("\$1"); shift ;;
    esac
  done
  exec "$real" test -v -run '$re' "\${args[@]}"
fi
exec "$real" "\$@"
EOF
  chmod +x "$shim/go"
  local tsv="$out/runs.tsv" i rc t0 dur pass fail log ok=0 bad=0
  : >"$tsv"
  printf 'run\trc\tseconds\tload1\tpass_lines\tfail_lines\tskip_lines\tlog\n' >>"$tsv"
  for i in $(seq 1 "$n"); do
    log="$out/run-$(printf '%03d' "$i").log"
    t0=$SECONDS
    local l0; l0="$(loadavg)"
    PATH="$shim:$PATH" "$@" >"$log" 2>&1 </dev/null
    rc=$?
    dur=$((SECONDS - t0))
    pass=$(grep -c -e '^ *--- PASS' "$log"); fail=$(grep -c -e '^ *--- FAIL' "$log"); skip=$(grep -c -e '^ *--- SKIP' "$log")
    if [ "$rc" = 0 ] && [ "$pass" -ge 1 ] && [ "$skip" = 0 ]; then
      ok=$((ok + 1)); r=PASS
      [ "${QV_REPEAT_KEEP:-0}" = 1 ] || { rm -f "$log"; log=-; }
    else
      bad=$((bad + 1)); r=FAIL
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$i" "$rc" "$dur" "$l0" "$pass" "$fail" "$skip" "$log" >>"$tsv"
    printf '  run %3d/%d  %s  %4ds  load %s%s\n' "$i" "$n" "$r" "$dur" "$l0" "$([ "$r" = FAIL ] && printf '  %s' "$log")"
  done
  printf 'e2e-repeat: %d of %d runs passed, %d did not (%s); table: %s\n' "$ok" "$n" "$bad" "$re" "$tsv"
  [ "$bad" = 0 ]
}

if [ "${1:-}" = engine ]; then shift; engine "$@"; exit $?; fi

n=20
while getopts n: o; do case "$o" in n) n=$OPTARG ;; *) die "usage: $0 [-n runs] <group|core> <TestRegexp>" ;; esac; done
shift $((OPTIND - 1))
[ $# -eq 2 ] || die "usage: $0 [-n runs] <group|core> <TestRegexp>   (groups: see scripts/e2e-all.sh; core: mpc-party with -race -tags teesim)"
group=$1; re=$2
out="${QV_E2E_OUT:-$ROOT/data/e2e-repeat/$(date +%Y%m%d-%H%M%S)}"

case "$group" in
  core)
    [ -d mpc-party/.deps ] || die "cb-mpc is not built: run make mpc-build first"
    . "$ROOT/scripts/lib-pins.sh"
    qv_load_pins --so || die "no SoftHSM PINs (make dev-env)"
    mkdir -p "$out"
    QV_SOFTHSM_DIR="$out/softhsm" ./scripts/setup-softhsm.sh >"$out/softhsm-setup.log" 2>&1 || die "softhsm set-up failed, see $out/softhsm-setup.log"
    export SOFTHSM2_CONF="$out/softhsm/softhsm2.conf" QV_REQUIRE_HSM=1
    engine "$n" "$re" "$out" -- bash -c 'cd mpc-party && go test -race -count=1 -timeout 25m -tags teesim -v ./e2e'
    ;;
  *)
    QV_E2E_OUT="$out" QV_E2E_REPEAT="$n" QV_E2E_RUN="$re" QV_E2E_GROUPS="$group" LANES=1 exec scripts/e2e-all.sh
    ;;
esac
