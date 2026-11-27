#!/usr/bin/env bash
# The `changes` job of .github/workflows/ci.yml: decides whether the heavy jobs may be skipped, and says so in the log, the step outputs and the run summary.
#
# The rule (the human's): "Make sure that changing related code can never accidentally skip a CI job that should run. Better to run too much than to miss
# a run." A skip needs proof: a pull request whose every changed file is on the allowlist ci/skip-allowlist. Everything else runs everything.
# A change that is not a skip of everything may still skip SOME jobs: ci/jobselect says which jobs no changed file can affect (output skip_jobs, the job
# ids with a comma before and after each: ",e2e-btc-cold,image,"). A job is skipped only by its own id in that list; an empty or missing list runs every job.
# Fail open: this script prints `skip=true` only at the very end of a clean decision. Any error, any other event, any surprise ends in `skip=false`
# (the EXIT trap writes it when no decision was made), and the workflow treats everything but the exact value `true` as "run everything".
#
# Inputs (environment): QV_EVENT_NAME (github.event_name), QV_PR_HEAD_SHA (github.event.pull_request.head.sha). Run in a checkout with full history of the
# pull request, at the merge commit GitHub makes for it (actions/checkout of a pull_request event, fetch-depth 0).
# Force a full run: put the words [ci full] in the message of any commit of the pull request (git commit --allow-empty -m "ci: full run [ci full]").
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
decided=0

emit() { # emit <skip true|false> <class> <count> <text>
  decided=1
  local skip="$1" class="$2" count="$3" text="$4"
  echo "$text"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    { echo "skip=$skip"; echo "class=$class"; echo "count=$count"; echo "text=$text"; } >> "$GITHUB_OUTPUT"
  fi
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    { echo "### ci: $text"; echo; echo "Rule: the heavy jobs are skipped only when every changed file is on ci/skip-allowlist; any doubt runs everything (CONTRIBUTING.md)."; } >> "$GITHUB_STEP_SUMMARY"
  fi
}
all() { emit false none 0 "running everything: $*"; exit 0; }
emit_jobs() { # emit_jobs ",<job>,<job>," <text>: skip those jobs, run the others. Written like emit: the decision ends the script.
  decided=1
  echo "$2"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    { echo "skip=false"; echo "class=jobs"; echo "count=0"; echo "text=$2"; echo "skip_jobs=$1"; } >> "$GITHUB_OUTPUT"
  fi
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    { echo "### ci: $2"; echo; echo "Rule: a job is skipped only when no changed file can affect it (ci/jobselect: the Go package graph, ci/job-rules); any doubt runs everything (CONTRIBUTING.md)."; } >> "$GITHUB_STEP_SUMMARY"
  fi
  exit 0
}
trap '[ "$decided" = 1 ] || emit false none 0 "running everything: the classifier did not finish"' EXIT

[ "${QV_EVENT_NAME:-}" = pull_request ] || all "event ${QV_EVENT_NAME:-unknown} always runs everything"
[ -n "${QV_PR_HEAD_SHA:-}" ] || all "no pull request head sha"

# the merge commit GitHub checks out: HEAD = merge of <base> (parent 1) and <head> (parent 2)
read -r -a revs < <(git rev-list --parents -n 1 HEAD 2>/dev/null) || all "cannot read HEAD"
[ "${#revs[@]}" = 3 ] || all "HEAD is not a merge commit of the pull request (${#revs[@]} fields)"
base="${revs[1]}"; head="${revs[2]}"
[ "$head" = "$QV_PR_HEAD_SHA" ] || all "the merge commit's second parent is not the pull request head"

msgs="$(git log --format=%B "$base..$head" 2>/dev/null)" || all "cannot read the commit messages"
case "$msgs" in *'[ci full]'*) all "a commit message asks for a full run ([ci full])" ;; esac

list="$(mktemp)"; trap 'rm -f "$list"; [ "$decided" = 1 ] || emit false none 0 "running everything: the classifier did not finish"' EXIT
git diff --raw -z --no-renames --no-abbrev "$base" HEAD > "$list" 2>/dev/null || all "cannot list the changed files"

verdict="$("$here/classify.sh" < "$list")" || all "the classifier failed"
if [[ "$verdict" == "all "* && "$verdict" != *$'\n'* ]]; then
  # Not a skip of everything: which jobs can the change affect? ci/jobselect (the Go package graph and ci/job-rules) answers "skip <job>..." or
  # "all <reason>". Anything else, an error, a crash or a timeout: everything runs.
  # built from this script's checkout, run in the checkout being classified (the same one in CI)
  bin="$(mktemp -d)/jobselect"; trap 'rm -f "$list" "$bin"; [ "$decided" = 1 ] || emit false none 0 "running everything: the classifier did not finish"' EXIT
  (cd "$here/.." && go build -o "$bin" ./ci/jobselect) || all "cannot build the job selector"
  to=(); command -v timeout >/dev/null && to=(timeout 300)
  sel="$(${to[@]+"${to[@]}"} "$bin" select < "$list")" || all "the job selector failed"
  if [[ "$sel" =~ ^skip((\ [a-z0-9][a-z0-9-]*)*)$ ]]; then
    skips="${BASH_REMATCH[1]}"
    n="$(wc -w <<< "$skips" | tr -d ' ')"
    [ "$n" -gt 0 ] || all "every job can be affected by the change"
    emit_jobs ",$(tr ' ' ',' <<< "${skips# }")," "running only the jobs the change can affect; skipped $n:$skips"
  elif [[ "$sel" == "all "* && "$sel" != *$'\n'* ]]; then
    all "${sel#all }"
  else
    all "unexpected job selector output"
  fi
fi
if [[ "$verdict" =~ ^skip\ (docs|chart|docs\+chart)\ ([0-9]+)$ ]]; then
  class="${BASH_REMATCH[1]}"; count="${BASH_REMATCH[2]}"
  case "$class" in
    docs) what="documentation-only change" ;;
    chart) what="chart-only change" ;;
    *) what="documentation and chart change" ;;
  esac
  emit true "$class" "$count" "skipped: $what ($count files, all on the allowlist); the heavy jobs did not run"
elif [[ "$verdict" == "all "* && "$verdict" != *$'\n'* ]]; then
  all "${verdict#all }"
else
  all "unexpected classifier output"
fi
