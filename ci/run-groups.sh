#!/usr/bin/env bash
# Runs several test groups one after another in one CI job, each in the CI image, each with its own time limit and environment, and ALL of them even
# when one fails: a failure in the first group must not hide the others. Prints one line per group (also to the run summary) and fails when any failed.
#   ci/run-groups.sh '<name>|<minutes>|<command>' ...
#   ci/run-groups.sh 'recovery|30|QV_E2E_TIMEOUT_SCALE=3 make test-e2e-btc-recovery' 'deposits|20|QV_E2E_TIMEOUT_SCALE=3 make test-e2e-btc-deposits'
# The command runs with bash -c inside ci/run-in-image.sh (the job's QV_* environment is passed in).
set -uo pipefail
cd "$(dirname "$0")/.."
[ $# -gt 0 ] || { echo "usage: ci/run-groups.sh '<name>|<minutes>|<command>'..." >&2; exit 2; }
runner="${QV_RUN_GROUPS_RUNNER:-ci/run-in-image.sh}"   # tests replace it
lines=(); failed=0
for spec in "$@"; do
  IFS='|' read -r name minutes cmd <<< "$spec"
  if [ -z "$name" ] || [ -z "$cmd" ] || ! [[ "$minutes" =~ ^[0-9]+$ ]]; then echo "run-groups: bad group '$spec'" >&2; exit 2; fi
  echo "::group::$name ($cmd, limit ${minutes}m)"
  start=$(date +%s)
  timeout --signal=TERM --kill-after=60 "${minutes}m" $runner bash -c "$cmd"; rc=$?
  secs=$(( $(date +%s) - start ))
  echo "::endgroup::"
  case "$rc" in
    0) result=pass ;;
    124|137) result="TIMEOUT after ${minutes}m"; failed=1 ;;
    *) result="FAIL (exit $rc)"; failed=1 ;;
  esac
  [ "$rc" = 0 ] || echo "::error title=$name::$name: $result"
  lines+=("$(printf '| %s | %s | %dm%02ds |' "$name" "$result" $((secs / 60)) $((secs % 60)))")
done
{ echo "| group | result | time |"; echo "|---|---|---|"; printf '%s\n' "${lines[@]}"; } | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
exit "$failed"
