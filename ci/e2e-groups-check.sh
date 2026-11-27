#!/usr/bin/env bash
# The end-to-end groups run several to a CI job (ci/run-groups.sh). This check, in the `changes` job on every run, makes sure no group is lost:
#   - every test-e2e-* target of the Makefile, and test-mpc, test-archive and load-smoke, is run by some ci.yml job, except the reviewed ones below
#     that are not pull-request groups;
#   - ci/run-groups.sh runs every group and fails when one fails; ci/gotest.sh passes go test's flags to a prebuilt test binary, and runs go test
#     itself for anything else.
#   ci/e2e-groups-check.sh             the check
#   ci/e2e-groups-check.sh --list-ci   print "<make target> <test>" for every make target ci.yml runs with go test (the tests CI runs, from the source:
#                                      `func TestX(t *testing.T)` filtered by the target's -run and -skip, as go test does)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
export GOFLAGS=-mod=readonly GOPROXY=off  # listing files needs no module download
wf=.github/workflows/ci.yml
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
bad=0
fail() { bad=1; echo "e2e-groups-check: $*"; }

# not pull-request groups: run by nightly.yml or by people (reviewed)
NOT_PR="test-e2e-evm test-e2e-evm-failure test-e2e-evm-latency test-e2e-all"

# tests <make target>: the top-level test names its go test command(s) run, sorted
tests() {
  local t="$1" cmds line run skip pkgs files
  cmds="$(make -n "$t" 2>/dev/null | grep -E '(^|[ ;&])go test ')" || { echo "ERROR: make -n $t has no go test command" >&2; return 1; }
  while IFS= read -r line; do
    run="$(printf '%s\n' "$line" | sed -nE "s/.* -run '([^']*)'.*/\1/p")"
    skip="$(printf '%s\n' "$line" | sed -nE "s/.* -skip '([^']*)'.*/\1/p")"
    pkgs="$(printf '%s\n' "${line#*go test }" | sed -E "s/'[^']*'//g" | tr ' ' '\n' | grep -E '^\./')" || return 1
    # shellcheck disable=SC2086
    files="$(go list -e -f '{{range .TestGoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .XTestGoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}' $pkgs 2>/dev/null)" || return 1
    # shellcheck disable=SC2086
    printf '%s\n' $files | xargs sed -nE 's/^func (Test([^a-z][A-Za-z0-9_]*)?)\([A-Za-z_][A-Za-z0-9_]* \*testing\.T\).*/\1/p' |
      { if [ -n "$run" ]; then grep -E -- "$run"; else cat; fi; } | { if [ -n "$skip" ]; then grep -vE -- "$skip"; else cat; fi; } || true
  done <<< "$cmds" | sort
}

if [ "${1:-}" = --list-ci ]; then
  for t in $(grep -oE 'make +[A-Za-z0-9_.-]+' "$wf" | awk '{print $2}' | sort -u); do
    make -n "$t" 2>/dev/null | grep -qE '(^|[ ;&])go test ' || continue
    tests "$t" | sed "s/^/$t /"
  done
  exit 0
fi

# 1. every group is run by some job
for t in $(grep -oE '^test-e2e-[a-z0-9-]+:' Makefile | tr -d ':') test-mpc test-archive load-smoke; do
  case " $NOT_PR " in *" $t "*) continue ;; esac
  grep -qE "make +$t( |'|$)" "$wf" || fail "no ci.yml job runs make $t (a group of the Makefile; add it to a job, or to NOT_PR with the reason)"
done
for t in $NOT_PR; do grep -qE "^$t:" Makefile || fail "NOT_PR names $t, which is not a Makefile target"; done

# 2. the runner of the groups: all run, a failure fails the step, the summary has every group
out="$(QV_RUN_GROUPS_RUNNER=env GITHUB_STEP_SUMMARY=/dev/null ci/run-groups.sh 'a|1|echo ran-a' 'b|1|exit 3' 'c|1|echo ran-c' 2>&1)"; rc=$?
[ "$rc" != 0 ] || fail "run-groups: a failed group must fail the step"
for w in ran-a ran-c '| a | pass' '| b | FAIL (exit 3)' '| c | pass'; do grep -qF -- "$w" <<< "$out" || fail "run-groups: '$w' missing from its output"; done
QV_RUN_GROUPS_RUNNER=env GITHUB_STEP_SUMMARY=/dev/null ci/run-groups.sh 'a|1|true' 'b|1|true' > /dev/null 2>&1 || fail "run-groups: all passing must pass"
QV_RUN_GROUPS_RUNNER=env ci/run-groups.sh 'a|x|true' > /dev/null 2>&1 && fail "run-groups: a bad time limit must be refused"

# 3. gotest.sh: the flags reach the prebuilt binary; anything else runs the real go test (a fake go records it)
mkdir -p "$tmp/tb" "$tmp/fake" "$tmp/pkg/e2e/x"
printf '#!/bin/sh\necho "BIN $PWD $*"\n' > "$tmp/tb/e2e_x.test"; chmod +x "$tmp/tb/e2e_x.test"
printf './e2e/x/...\te2e/x\n' > "$tmp/tb/manifest"
printf '#!/bin/sh\necho "GO $*"\n' > "$tmp/fake/go"; chmod +x "$tmp/fake/go"
mkdir -p "$tmp/pkg/ci"; cp ci/gotest.sh "$tmp/pkg/ci/"
gt() { PATH="$tmp/fake:$PATH" QV_E2E_TESTBIN="$tmp/tb" "$tmp/pkg/ci/gotest.sh" "$@" 2>/dev/null; }
got="$(gt -count=1 -p 1 -timeout 25m -v -run 'A|B' -skip 'C' ./e2e/x/...)"
[[ "$got" == "BIN $tmp/pkg/e2e/x -test.count=1 -test.timeout=25m -test.v -test.run=A|B -test.skip=C -test.paniconexit0"* ]] || [[ "$got" == *"-test.count=1 -test.v -test.run=A|B -test.skip=C -test.timeout=25m -test.paniconexit0"* ]] || fail "gotest: flags not passed as go test would: $got"
[[ "$(gt -count=1 -race ./e2e/x/...)" == "GO test -count=1 -race ./e2e/x/..." ]] || fail "gotest: an unknown flag must run go test"
[[ "$(gt -count=1 ./e2e/y/...)" == "GO test -count=1 ./e2e/y/..." ]] || fail "gotest: a pattern not in the manifest must run go test"
[[ "$(PATH="$tmp/fake:$PATH" QV_E2E_TESTBIN= "$tmp/pkg/ci/gotest.sh" -count=1 ./e2e/x/... 2>/dev/null)" == "GO test -count=1 ./e2e/x/..." ]] || fail "gotest: without QV_E2E_TESTBIN it must run go test"
[ "$bad" = 0 ] && echo "e2e-groups-check: ok (every group runs in a job; the runner and gotest.sh behave)"
[ "$bad" = 0 ]
