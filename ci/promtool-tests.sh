#!/usr/bin/env bash
# The Prometheus rule checks, run in the CI image (ci/run-in-image.sh ci/promtool-tests.sh), where promtool is pinned (ci/qv-ci.Dockerfile).
# 1. promtool itself on monitoring/: check rules, check config, the rule unit tests.
# 2. The Go tests that use promtool, verbose. They skip when promtool is missing; here a skip is a failure, and so is a missing PASS line.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v promtool >/dev/null || { echo "promtool is not in the image" >&2; exit 1; }
promtool --version | head -1
(
  cd monitoring
  promtool check rules ./*.rules.yml
  promtool check config prometheus.yml
  promtool test rules ./*.rules.test.yml
)
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
rc=0
{
  go test -count=1 -v ./monitoring/
  (cd mpc-party && go test -count=1 -v -run '^TestFailCountCryptographicOnEachLink$' ./internal/server)
} 2>&1 | tee "$out" || rc=$?
[ "$rc" -eq 0 ] || exit "$rc"
if grep -E '^\s*--- SKIP' "$out"; then echo "a promtool test was skipped: that is a failure in CI" >&2; exit 1; fi
for t in TestRuleFilesPassPromtoolCheck TestPrometheusConfigPassesPromtoolCheck TestRulesUnitTestsPassPromtool TestFailCountCryptographicOnEachLink; do
  grep -qE "^--- PASS: $t " "$out" || { echo "$t did not run and pass" >&2; exit 1; }
done
