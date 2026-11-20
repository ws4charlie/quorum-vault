#!/usr/bin/env bash
# One lane per checkout: the compose project name, the host-port block and a machine-wide limit on running lanes, so e2e runs of several
# worktrees on one machine do not touch each other. Used by the Makefile, scripts/e2e-all.sh and by hand:
#   scripts/e2e-lane.sh show         this checkout's project name and ports
#   scripts/e2e-lane.sh vars         K=V lines the Makefile imports (nothing in CI; the environment always wins)
#   scripts/e2e-lane.sh slots        who holds the lane slots now
#   scripts/e2e-lane.sh clean        remove the compose projects of THIS checkout (containers, volumes, networks)
#   scripts/e2e-lane.sh clean-stale  list, then remove, projects whose checkout directory no longer exists
# Sourced (by scripts/e2e-all.sh) it gives lane_project, lane_port_base, lane_acquire <units> <what> and lane_release.
#
# Names: project qve2e-<first 6 hex of sha1(checkout path)>; ports: a block of 100 from 12000 (below the OS's ephemeral ranges), the first block
# no other existing checkout has claimed, starting at a hash-chosen one; claims are files in $QV_E2E_STATE/blocks (default ~/.cache/qv-e2e).
# Off in CI (CI or GITHUB_ACTIONS set, or inside the CI image, /opt/qv-ci): the fixed names and ports stay. QV_E2E_LANE=0 turns it off, =1 on.
# Limit: QV_E2E_MAX_LANES (default min(CPUs/2, GB of memory/4), 2 to 16). A run takes one unit per lane it starts.
set -uo pipefail

_lane_root() { (cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P); }
LANE_ROOT="$(_lane_root)"
LANE_STATE="${QV_E2E_STATE:-$HOME/.cache/qv-e2e}"

_lane_hash() { printf '%s' "$1" | { shasum 2>/dev/null || sha1sum; } | cut -c1-6; }
lane_active() {
  case "${QV_E2E_LANE:-}" in 0) return 1 ;; 1) return 0 ;; esac
  [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -d /opt/qv-ci ] && return 1
  return 0
}
lane_project() { if lane_active; then echo "qve2e-$(_lane_hash "$LANE_ROOT")"; else echo qve2e; fi; }

# the block: claim it once, reuse it for good (until the checkout directory is gone)
lane_block() {
  local d="$LANE_STATE/blocks" f idx start k
  mkdir -p "$d"
  for f in "$d"/*; do [ -f "$f" ] && [ "$(cat "$f")" = "$LANE_ROOT" ] && { echo "${f##*/}"; return; }; done
  start=$(( 16#$(_lane_hash "$LANE_ROOT") % 200 ))
  for k in $(seq 0 199); do
    idx=$(( (start + k) % 200 ))
    f="$d/$idx"
    if [ -f "$f" ] && [ ! -d "$(cat "$f")" ]; then rm -f "$f"; fi # its checkout is gone
    if ( set -C; printf '%s' "$LANE_ROOT" >"$f" ) 2>/dev/null; then echo "$idx"; return; fi
  done
  echo "e2e-lane: all 200 port blocks are claimed (see $d); run: make e2e-clean-stale" >&2
  return 1
}
lane_port_base() {
  if [ -n "${QV_E2E_PORT_BASE:-}" ]; then echo "$QV_E2E_PORT_BASE"; return; fi
  if lane_active; then echo $(( 12000 + 100 * $(lane_block) )); else echo 41000; fi
}

# ports of the single-stack targets (db-up, infra-up, btc-up ...) sit at the top of the block; scripts/e2e-all.sh uses 1..3 and 10n..10n+4 (n<=8)
_lane_vars() {
  local b p
  b=$(lane_port_base) || return 1
  p=$(lane_project)
  cat <<EOF
COMPOSE_PROJECT_NAME=$p
QV_ARCHIVE_PORT=$((b + 89))
QV_PG_PORT=$((b + 90))
QV_SIGNING_DB_PORT=$((b + 91))
QV_ANVIL_PORT=$((b + 92))
QV_BTC_PORT=$((b + 93))
QV_SOL_PORT=$((b + 94))
QV_TEMPORAL_PORT=$((b + 95))
QV_KAFKA_PORT=$((b + 96))
QV_KEYCLOAK_PORT=$((b + 97))
QV_TEMPORAL_UI_PORT=$((b + 98))
QV_PROM_PORT=$((b + 99))
QV_ANVIL_RPC=http://127.0.0.1:$((b + 92))
QV_BTC_RPC=http://127.0.0.1:$((b + 93))
QV_SOL_RPC=http://127.0.0.1:$((b + 94))
QV_TEMPORAL_ADDR=127.0.0.1:$((b + 95))
QV_KAFKA_BROKERS=127.0.0.1:$((b + 96))
QV_E2E_KEYCLOAK_URL=https://127.0.0.1:$((b + 97))
EOF
}
lane_vars() { lane_active || return 0; local kv; _lane_vars | while IFS= read -r kv; do eval "[ -n \"\${${kv%%=*}:-}\" ]" || echo "$kv"; done; }

# ---- limit on running lanes ----
lane_limit() {
  [ -n "${QV_E2E_MAX_LANES:-}" ] && { echo "$QV_E2E_MAX_LANES"; return; }
  local cpu mem n
  cpu=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
  if [ -r /proc/meminfo ]; then mem=$(awk '/^MemTotal:/ {print int($2/1048576)}' /proc/meminfo)
  else mem=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 17179869184) / 1073741824 )); fi
  n=$(( cpu / 2 )); [ $(( mem / 4 )) -lt "$n" ] && n=$(( mem / 4 ))
  [ "$n" -lt 2 ] && n=2; [ "$n" -gt 16 ] && n=16
  echo "$n"
}
_lane_dir() { echo "$LANE_STATE/slots"; }
_lane_lock() { # a mkdir lock held for milliseconds; one older than 30 s is a crashed holder's
  local l="$(_lane_dir).lock" t=0
  mkdir -p "$LANE_STATE"
  until mkdir "$l" 2>/dev/null; do
    if [ -d "$l" ] && [ -n "$(find "$l" -maxdepth 0 -mmin +0.5 2>/dev/null)" ]; then rmdir "$l" 2>/dev/null; fi
    sleep 0.2; t=$((t + 1)); [ "$t" -gt 300 ] && return 1
  done
}
_lane_unlock() { rmdir "$(_lane_dir).lock" 2>/dev/null; }
_lane_holders() { # prints "<file> <pid> <units> <started epoch> <path> <what>" for live holders; removes the dead ones
  local f pid units ts path what
  for f in "$(_lane_dir)"/*; do
    [ -f "$f" ] || continue
    IFS='|' read -r pid units ts path what <"$f"
    if kill -0 "$pid" 2>/dev/null; then echo "$f $pid $units $ts $path $what"; else rm -f "$f"; fi
  done
}
LANE_HELD=""
lane_acquire() { # lane_acquire <units> <what>: blocks until the units fit under the limit (all of it, if the run asks for more than the limit)
  local units=$1 what=$2 limit used held waited=0 line
  limit=$(lane_limit)
  [ "$units" -gt "$limit" ] && units=$limit
  mkdir -p "$(_lane_dir)"
  while :; do
    _lane_lock || { echo "e2e-lane: could not take the slot lock in $LANE_STATE" >&2; return 1; }
    used=0
    while read -r _ _ held _; do used=$((used + held)); done < <(_lane_holders)
    if [ "$used" -eq 0 ] || [ $((used + units)) -le "$limit" ]; then
      LANE_HELD="$(_lane_dir)/$$"
      printf '%s|%s|%s|%s|%s\n' "$$" "$units" "$(date +%s)" "$LANE_ROOT" "$what" >"$LANE_HELD"
      _lane_unlock
      [ "$waited" -gt 0 ] && echo "e2e-lane: got $units lane slot(s) after ${waited}s"
      return 0
    fi
    _lane_unlock
    if [ $((waited % 30)) -eq 0 ]; then
      echo "e2e-lane: waiting for lane slots ($used of $limit in use, this run needs $units; QV_E2E_MAX_LANES sets the limit). Held by:"
      _lane_holders | while read -r _ pid held ts path what; do
        echo "  pid $pid  $held slot(s)  for $(( ($(date +%s) - ts) / 60 )) min  $path  $what"
      done
    fi
    sleep 5; waited=$((waited + 5))
  done
}
lane_release() { [ -n "$LANE_HELD" ] && rm -f "$LANE_HELD"; LANE_HELD=""; return 0; }
lane_slots() {
  echo "limit $(lane_limit) lane slot(s); held:"
  _lane_holders | while read -r _ pid held ts path what; do echo "  pid $pid  $held slot(s)  for $(( ($(date +%s) - ts) / 60 )) min  $path  $what"; done
}

# ---- clean-up: only by compose labels and the project name of the checkout, never by guessing ----
_docker_ok() { command -v docker >/dev/null && docker info >/dev/null 2>&1 || { echo "e2e-lane: docker is not running" >&2; return 1; }; }
_remove_project() { # _remove_project <project>
  local p=$1 ids
  ids=$(docker ps -aq --filter "label=com.docker.compose.project=$p")
  [ -n "$ids" ] && docker rm -fv $ids >/dev/null
  ids=$(docker network ls -q --filter "label=com.docker.compose.project=$p")
  [ -n "$ids" ] && docker network rm $ids >/dev/null 2>&1
  ids=$(docker volume ls -q --filter "label=com.docker.compose.project=$p")
  [ -n "$ids" ] && docker volume rm -f $ids >/dev/null 2>&1
  return 0
}
_all_projects() { # every compose project with something left: "<project> <working_dir>" (working dir "-" when only volumes or networks remain)
  { docker ps -a --format '{{.Label "com.docker.compose.project"}} {{.Label "com.docker.compose.project.working_dir"}}'
    docker volume ls --format '{{.Label "com.docker.compose.project"}} -'
    docker network ls --format '{{.Label "com.docker.compose.project"}} -'; } | awk 'NF==2 && $1!="" {print}' | sort -u
}
lane_clean() {
  _docker_ok || return 1
  local h p dir n=0
  h=$(_lane_hash "$LANE_ROOT")
  _all_projects | while read -r p dir; do
    case "$p" in "qve2e-$h"|"qve2e-$h"-*) ;; *) [ "$dir" = "$LANE_ROOT" ] || continue ;; esac
    echo "removing $p"; _remove_project "$p"
  done
  echo "e2e-lane: clean for $LANE_ROOT"
}
lane_clean_stale() {
  _docker_ok || return 1
  local p dir list="" h f path
  # projects with a working directory that is gone (also what was started by hand under any name)
  list=$(_all_projects | while read -r p dir; do [ "$dir" != "-" ] && [ ! -d "$dir" ] && echo "$p $dir"; done | sort -u)
  # project names of checkouts that registered a block and are gone (their volumes and networks carry no directory)
  for f in "$LANE_STATE"/blocks/*; do
    [ -f "$f" ] || continue
    path=$(cat "$f")
    [ -d "$path" ] && continue
    h=$(_lane_hash "$path")
    _all_projects | while read -r p dir; do case "$p" in "qve2e-$h"|"qve2e-$h"-*) echo "$p $path" ;; esac; done
  done > "$LANE_STATE/.stale.$$" 2>/dev/null
  list=$(printf '%s\n%s\n' "$list" "$(cat "$LANE_STATE/.stale.$$")" | awk 'NF' | sort -u); rm -f "$LANE_STATE/.stale.$$"
  if [ -z "$list" ]; then echo "e2e-lane: no stale projects"; else
    echo "stale compose projects (their checkout directory no longer exists):"
    printf '%s\n' "$list" | sed 's/^/  /'
    printf '%s\n' "$list" | while read -r p dir; do echo "removing $p"; _remove_project "$p"; done
  fi
  for f in "$LANE_STATE"/blocks/*; do [ -f "$f" ] && [ ! -d "$(cat "$f")" ] && rm -f "$f"; done
  return 0
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-show}" in
    show) echo "checkout $LANE_ROOT"; lane_active && echo "lane on" || echo "lane off (CI, or QV_E2E_LANE=0): fixed names and ports"; _lane_vars | sed 's/^/  /' ;;
    vars) lane_vars ;;
    slots) lane_slots ;;
    clean) lane_clean ;;
    clean-stale) lane_clean_stale ;;
    *) echo "usage: $0 show|vars|slots|clean|clean-stale" >&2; exit 2 ;;
  esac
fi
