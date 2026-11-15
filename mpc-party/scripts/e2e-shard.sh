#!/usr/bin/env bash
# Splits the tests of the mpc-party/e2e package into CI shards and runs one of them (same flags as the single `go test -race ./...` it replaced).
#   scripts/e2e-shard.sh run <n>      checks the split, then runs shard n (1..SHARDS) under -race
#   scripts/e2e-shard.sh check        checks the split only
#   scripts/e2e-shard.sh list <n>     prints the tests of shard n
# The tests come from `go test -list`, so a new test lands in exactly one shard by itself: the heavy ones are pinned below to balance the time
# (measured under -race on a CI runner, seconds), every other test goes to DEFAULT_SHARD. The check fails when a pinned name is not a test any more
# (a rename would silently move it to the default shard), when a test is in no shard or in two, or when the shards do not add up to the list.
set -euo pipefail
cd "$(dirname "$0")/.."

SHARDS=3
DEFAULT_SHARD=3
# shard <TAB> test
PINS="1	TestCrashMatrixThresholdRefresh
1	TestCrashMatrixRefresh
2	TestCrashMatrixThresholdDKG
2	TestCrashMatrixDKG
2	TestThresholdBackupRestoreLostMember
2	TestReconcileLatencyAfterRestart"

tests="$(go test -race -list '.*' ./e2e | grep -E '^(Test|Fuzz|Example)' | sort)"
[ -n "$tests" ] || { echo "e2e-shard: no tests listed" >&2; exit 1; }

# assign: one "shard<TAB>test" line per listed test
assign="$(while read -r t; do
  s="$(awk -F'\t' -v t="$t" '$2==t {print $1}' <<<"$PINS")"
  printf '%s\t%s\n' "${s:-$DEFAULT_SHARD}" "$t"
done <<<"$tests")"
list_shard() { awk -F'\t' -v n="$1" '$1==n {print $2}' <<<"$assign"; }
count=$(wc -l <<<"$tests" | tr -d ' ')

check() {
  local bad=0 n t total=0 c
  # every pin names a real test, once, in a real shard
  while IFS=$'\t' read -r n t; do
    [ -n "$t" ] || continue
    grep -qx "$t" <<<"$tests" || { echo "e2e-shard: pinned test $t does not exist (renamed or removed?)" >&2; bad=1; }
    c="$(awk -F'\t' -v t="$t" '$2==t' <<<"$PINS" | wc -l | tr -d ' ')"
    [ "$c" = 1 ] || { echo "e2e-shard: $t is pinned $c times" >&2; bad=1; }
    { [ "$n" -ge 1 ] && [ "$n" -le "$SHARDS" ]; } || { echo "e2e-shard: $t is pinned to shard $n of $SHARDS" >&2; bad=1; }
  done <<<"$PINS"
  # every listed test is in exactly one shard, and the shards add up to the list
  for t in $tests; do
    c="$(awk -F'\t' -v t="$t" '$2==t' <<<"$assign" | wc -l | tr -d ' ')"
    [ "$c" = 1 ] || { echo "e2e-shard: $t is in $c shards" >&2; bad=1; }
  done
  for n in $(seq 1 "$SHARDS"); do total=$((total + $(list_shard "$n" | wc -l))); done
  [ "$total" = "$count" ] || { echo "e2e-shard: shards hold $total tests, the package has $count" >&2; bad=1; }
  [ "$bad" = 0 ] || exit 1
  echo "e2e-shard: ok, $count tests: $(for n in $(seq 1 "$SHARDS"); do printf 'shard %s %s  ' "$n" "$(list_shard "$n" | wc -l | tr -d ' ')"; done)"
}

case "${1:-}" in
check) check ;;
list) list_shard "${2:?shard number}" ;;
run)
  n="${2:?shard number}"
  check
  mine="$(list_shard "$n")"
  [ -n "$mine" ] || { echo "e2e-shard: shard $n is empty" >&2; exit 1; }
  echo "e2e-shard: shard $n runs: $(echo $mine)"
  exec go test -race -count=1 -timeout 25m -run "^($(echo "$mine" | paste -sd'|' -))\$" ./e2e
  ;;
*) echo "usage: $0 run <n> | check | list <n>" >&2; exit 2 ;;
esac
