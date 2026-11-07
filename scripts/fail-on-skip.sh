#!/usr/bin/env bash
# Runs a `go test -v` command and fails when its output has a skipped test. The Bitcoin e2e groups run through it (Makefile), so a test that skips
# cannot leave a job green: a test that cannot run must fail, not vanish.
set -uo pipefail
out=$(mktemp)
trap 'rm -f "$out"' EXIT
"$@" 2>&1 | tee "$out"
rc=${PIPESTATUS[0]}
if grep -q -e '--- SKIP' "$out"; then
	echo >&2 "fail-on-skip: the run skipped tests, which this group does not allow:"
	grep >&2 -e '--- SKIP' "$out"
	exit 1
fi
exit "$rc"
