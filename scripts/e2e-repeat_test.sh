#!/usr/bin/env bash
# Test of the loop in scripts/e2e-repeat.sh with a fake `go`: the counting of passes (N of N, a failure, a skip, a pattern that matches nothing, a flaky
# test), and that every kind of command the script runs (a CI group's go test with -run, one with -run=, the `test` group's without -v, the core
# command with no -run, `go vet` before it) gets -v and the -run it was given. No services, no Go build.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat >"$tmp/bin/go" <<'FAKE'
#!/usr/bin/env bash
# fake go: `vet` succeeds; `test` prints "--- PASS" only with -v, as the real one does, and acts as FAKE_MODE says; the arguments are kept
echo "$*" >>"$FAKE_ARGS"
[ "${1:-}" = vet ] && exit 0
[ "${1:-}" = test ] || exit 0
v=0; for a in "$@"; do [ "$a" = -v ] && v=1; done
n=$(wc -l <"$FAKE_ARGS" | tr -d ' ')
case "$FAKE_MODE" in
  pass) [ $v = 1 ] && echo "--- PASS: TestX (0.1s)"; exit 0 ;;
  fail) [ $v = 1 ] && echo "--- FAIL: TestX (0.1s)"; exit 1 ;;
  skip) [ $v = 1 ] && { echo "--- PASS: TestX (0.1s)"; echo "    --- SKIP: TestX/sub (0.0s)"; }; exit 0 ;;
  nomatch) echo "testing: warning: no tests to run"; exit 0 ;;
  flaky) if [ $((n % 2)) = 0 ]; then [ $v = 1 ] && echo "--- PASS: TestX"; exit 0; else [ $v = 1 ] && echo "--- FAIL: TestX"; exit 1; fi ;;
esac
FAKE
chmod +x "$tmp/bin/go"
fails=0; total=0
# check <description> <mode> <expected passes of 3> <command...>
check() {
  local desc="$1" mode="$2" want="$3"; shift 3
  local out rc wantrc=0; [ "$want" != 3 ] && wantrc=1
  : >"$tmp/args"; total=$((total + 1))
  out="$(PATH="$tmp/bin:$PATH" FAKE_MODE="$mode" FAKE_ARGS="$tmp/args" "$here/e2e-repeat.sh" engine 3 TestX "$tmp/out$total" -- "$@" 2>&1)"; rc=$?
  if ! printf '%s' "$out" | grep -q "$want of 3 runs passed" || { [ $wantrc = 0 ] && [ $rc != 0 ]; } || { [ $wantrc = 1 ] && [ $rc = 0 ]; }; then
    fails=$((fails + 1)); echo "FAIL: $desc: wanted $want of 3 and exit $wantrc, got exit $rc:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi
  # every go test got -v and -run TestX, and none kept another -run
  if grep '^test ' "$tmp/args" | grep -v -e ' -v ' -e '^test -v ' | grep -q .; then fails=$((fails + 1)); echo "FAIL: $desc: a go test ran without -v"; fi
  if grep '^test ' "$tmp/args" | grep -v -e '-run TestX' | grep -q .; then fails=$((fails + 1)); echo "FAIL: $desc: a go test ran without -run TestX"; fi
  if grep '^test ' "$tmp/args" | grep -q -e 'OLD'; then fails=$((fails + 1)); echo "FAIL: $desc: the old -run was kept"; fi
}
group='go test -count=1 -p 1 -timeout 25m -v -run OLD ./e2e/x/...'
check "a group: N of N pass"                       pass    3 bash -c "$group"
check "a group with -run=: N of N pass"            pass    3 bash -c 'go test -count=1 -run=OLD ./e2e/x/...'
check "the test group without -v and with go vet"  pass    3 bash -c 'go vet ./... && go test -short -count=1 -p 1 ./...'
check "core: no -run at all, -race, tags"          pass    3 bash -c 'cd . && go test -race -count=1 -tags teesim ./e2e'
check "a failing test is counted"                  fail    0 bash -c "$group"
check "a skip is not a pass"                       skip    0 bash -c "$group"
check "a pattern that matches nothing is no pass"  nomatch 0 bash -c "$group"
check "a flaky test: counted per run"              flaky   1 bash -c "$group"
[ "$fails" = 0 ] && echo "e2e-repeat_test: $total cases ok" && exit 0
exit 1
