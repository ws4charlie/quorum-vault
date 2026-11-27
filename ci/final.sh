#!/usr/bin/env bash
# The last step of the `changes` job: the ONE place that publishes the job output `skip`. It is `true` only when the classifier said skip AND every guard and
# test step of the same job succeeded. Anything else (a step that failed, timed out, was cancelled or skipped; a classifier that crashed; a missing value)
# publishes `false`. The step itself runs only when every earlier step succeeded, so a failed guard normally leaves the output empty; this script makes the
# composition explicit and testable (ci/changes_test.sh).
# The same for `skip_jobs` (the jobs ci/jobselect says the change cannot affect): published only when every guard succeeded and the value is a clean list.
# Environment: QV_CLASSIFY_OUTCOME (steps.classify.outcome), QV_CLASSIFY_SKIP (its output skip), QV_CLASSIFY_SKIP_JOBS (its output skip_jobs),
# QV_CLASSIFY_TEXT, QV_GUARD_OUTCOMES (the outcomes of the guard and test steps, separated by spaces; at least 8).
set -uo pipefail
skip=false
n=0; allok=1
for o in ${QV_GUARD_OUTCOMES:-}; do n=$((n + 1)); [ "$o" = success ] || allok=0; done
if [ "$allok" = 1 ] && [ "$n" -ge 8 ] && [ "${QV_CLASSIFY_OUTCOME:-}" = success ] && [ "${QV_CLASSIFY_SKIP:-}" = true ]; then skip=true; fi
# the jobs to skip: only from a clean classify step whose every guard passed, and only a list of job ids (",a,b,"); anything else is empty (run all)
skip_jobs=""
if [ "$allok" = 1 ] && [ "$n" -ge 8 ] && [ "${QV_CLASSIFY_OUTCOME:-}" = success ] && [ "$skip" != true ] && [[ "${QV_CLASSIFY_SKIP_JOBS:-}" =~ ^(,[a-z0-9][a-z0-9-]*)+,$ ]]; then
  skip_jobs="$QV_CLASSIFY_SKIP_JOBS"
fi
text="${QV_CLASSIFY_TEXT:-}"
if [ "$skip" != true ] && [ -z "$skip_jobs" ]; then text="running everything"; fi
echo "skip=$skip skip_jobs=[$skip_jobs]: $text"
if [ -n "${GITHUB_OUTPUT:-}" ]; then { echo "skip=$skip"; echo "skip_jobs=$skip_jobs"; echo "text=$text"; } >> "$GITHUB_OUTPUT"; fi
