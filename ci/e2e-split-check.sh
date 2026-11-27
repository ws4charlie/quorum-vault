#!/usr/bin/env bash
# The slowest end-to-end groups run in CI as two jobs each (Makefile: test-e2e-<group>-1 and -2). Shard 1 runs the top-level tests it names, shard 2
# runs the group's own selector minus those names, so no test can be lost by construction. This script proves it on every run (the `changes` job):
#   - shard 1 and shard 2 together select exactly the tests the whole group selects, and no test is in both;
#   - each shard selects at least one test;
#   - ci.yml runs every shard target and no longer runs the whole group (a group run twice would only waste time; a shard not run would lose tests).
# The tests are listed from the source (`func TestX(t *testing.T)` in the package's test files, as go test finds them) and filtered with the -run and
# -skip of the target's command (`make -n`), the way go test applies them to top-level names. No compiling, no services.
#   ci/e2e-split-check.sh            check every split group
#   ci/e2e-split-check.sh --print    also print the test names of every group and shard
#   ci/e2e-split-check.sh --list-ci  print "<make target> <test>" for every make target that ci.yml runs with go test (the full set CI runs)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
export GOFLAGS=-mod=readonly GOPROXY=off  # listing files needs no module download

# group  shard-1  shard-2
SPLITS="
test-e2e-evm-flows test-e2e-evm-flows-1 test-e2e-evm-flows-2
test-e2e-sol-sweeps test-e2e-sol-sweeps-1 test-e2e-sol-sweeps-2
test-e2e-sol-cold test-e2e-sol-cold-1 test-e2e-sol-cold-2
test-e2e-btc-sweeps test-e2e-btc-sweeps-1 test-e2e-btc-sweeps-2
test-e2e-btc-recovery test-e2e-btc-recovery-1 test-e2e-btc-recovery-2
"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
bad=0
fail() { bad=1; echo "e2e-split-check: $*"; }

# tests <make target>: the top-level test names the target's go test command(s) run, one per line, sorted
tests() {
  local t="$1" cmds line run skip pkgs files
  cmds="$(make -n "$t" 2>/dev/null | grep -E '(^|[ ;&])go test ')" || { echo "ERROR: make -n $t has no go test command" >&2; return 1; }
  while IFS= read -r line; do
    run="$(printf '%s\n' "$line" | sed -nE "s/.* -run '([^']*)'.*/\1/p")"
    skip="$(printf '%s\n' "$line" | sed -nE "s/.* -skip '([^']*)'.*/\1/p")"
    case "$line" in *" -run "*) [ -n "$run" ] || { echo "ERROR: $t: cannot read -run" >&2; return 1; } ;; esac
    case "$line" in *" -skip "*) [ -n "$skip" ] || { echo "ERROR: $t: cannot read -skip" >&2; return 1; } ;; esac
    case "$line" in *" -tags "*|*'$('*|*'`'*) echo "ERROR: $t: a -tags flag or a shell expansion this check does not model" >&2; return 1 ;; esac
    # the package arguments: every word that starts with ./ (after the flags)
    pkgs="$(printf '%s\n' "${line#*go test }" | sed -E "s/'[^']*'//g" | tr ' ' '\n' | grep -E '^\./' )" || { echo "ERROR: $t: no package" >&2; return 1; }
    files="$(go list -e -f '{{range .TestGoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .XTestGoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}' $pkgs 2>/dev/null)" || { echo "ERROR: $t: go list $pkgs" >&2; return 1; }
    [ -n "$files" ] || { echo "ERROR: $t: no test files in $pkgs" >&2; return 1; }
    # shellcheck disable=SC2086
    printf '%s\n' $files | xargs sed -nE 's/^func (Test([^a-z][A-Za-z0-9_]*)?)\([A-Za-z_][A-Za-z0-9_]* \*testing\.T\).*/\1/p' |
      { if [ -n "$run" ]; then grep -E -- "$run"; else cat; fi; } |
      { if [ -n "$skip" ]; then grep -vE -- "$skip"; else cat; fi; } || true
  done <<< "$cmds" | sort
}

if [ "${1:-}" = --list-ci ]; then
  for t in $(grep -oE 'make +[A-Za-z0-9_.-]+' .github/workflows/ci.yml | awk '{print $2}' | sort -u); do
    make -n "$t" 2>/dev/null | grep -qE '(^|[ ;&])go test ' || continue
    tests "$t" | sed "s/^/$t /"
  done
  exit 0
fi

while read -r g s1 s2; do
  [ -n "$g" ] || continue
  tests "$g" > "$tmp/g" || { fail "$g: cannot list"; continue; }
  tests "$s1" > "$tmp/1" || { fail "$s1: cannot list"; continue; }
  tests "$s2" > "$tmp/2" || { fail "$s2: cannot list"; continue; }
  [ -s "$tmp/g" ] || fail "$g selects no test"
  [ -s "$tmp/1" ] || fail "$s1 selects no test (a name in its list is wrong?)"
  [ -s "$tmp/2" ] || fail "$s2 selects no test"
  both="$(comm -12 "$tmp/1" "$tmp/2")"; [ -z "$both" ] || fail "$s1 and $s2 both run: $(echo $both)"
  sort -u "$tmp/1" "$tmp/2" > "$tmp/u"
  lost="$(comm -23 "$tmp/g" "$tmp/u")"; [ -z "$lost" ] || fail "$g: run by no shard: $(echo $lost)"
  extra="$(comm -13 "$tmp/g" "$tmp/u")"; [ -z "$extra" ] || fail "$g: a shard runs a test the group does not: $(echo $extra)"
  # ci.yml runs both shards and not the whole group
  for s in "$s1" "$s2"; do grep -qE "make +$s( |$)" .github/workflows/ci.yml || fail "ci.yml does not run make $s"; done
  if grep -qE "make +$g( |$)" .github/workflows/ci.yml; then fail "ci.yml still runs the whole group make $g (run its shards instead)"; fi
  echo "e2e-split-check: $g = $s1 ($(wc -l < "$tmp/1" | tr -d ' ')) + $s2 ($(wc -l < "$tmp/2" | tr -d ' ')) tests: ok"
  if [ "${1:-}" = --print ]; then sed "s/^/  1 /" "$tmp/1"; sed "s/^/  2 /" "$tmp/2"; fi
done <<< "$SPLITS"
[ "$bad" = 0 ] || exit 1
