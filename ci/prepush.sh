#!/usr/bin/env bash
# The checks of the `changes` and `build` jobs that a CI change must pass locally before it is pushed (two pushes once failed CI within 30 seconds on
# exactly these). Run it on the branch merged with the latest origin/main:
#   git fetch origin && git merge origin/main && ci/prepush.sh
# Needs Go and Docker (the prebuild runs in the CI image, as the build job runs it). Exit 0 only if every step passed.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
step() { # step <name> <command...>
  local name="$1"; shift
  echo "== $name"
  if "$@"; then echo "== $name: ok"; else echo "== $name: FAILED"; fail=1; fi
}
behind="$(git rev-list --count HEAD..origin/main 2>/dev/null || echo '?')"
echo "== origin/main commits not merged into HEAD: $behind"
[ "$behind" = 0 ] || { echo "== merge origin/main first"; fail=1; }
step "go test ./ci/jobselect/..." go test -count=1 ./ci/jobselect/...
step "jobselect check" go run ./ci/jobselect check
step "ci/changes_test.sh" ci/changes_test.sh
step "ci/e2e-groups-check.sh" ci/e2e-groups-check.sh
step "ci/skip-guard_test.sh" ci/skip-guard_test.sh
step "ci/skip-guard.sh" ci/skip-guard.sh
step "ci/tracked-files.sh" ci/tracked-files.sh
step "e2e/mpcstack prebuilt keys" go test -count=1 -run 'Prebuilt|Prebuild|GoBuild' ./e2e/mpcstack
out=".ci-prebuilt"
step "the CI image" ci/ensure-image.sh use
step "ci/e2e-prebuild.sh in the CI image (as the build job runs it)" ci/run-in-image.sh ci/e2e-prebuild.sh "$out"
rm -rf "$out"
[ "$fail" = 0 ] && echo "prepush: every step passed" || echo "prepush: FAILED (above): do not push"
exit "$fail"
