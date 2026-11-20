#!/usr/bin/env bash
# Table test of the skip classifier (ci/classify.sh) and of the job's script (ci/changes.sh), run by the `changes` job of ci.yml on every run.
# The rule it proves: a skip happens only when every changed file is a plain add, modify or delete of a file on ci/skip-allowlist; every other case,
# every error and every other event runs everything. The pull request events are simulated with real merge commits in a scratch repository.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# counters live in files: the table cases run in pipelines, that is, in subshells
: > "$tmp/n"; : > "$tmp/f"
ok() { echo . >> "$tmp/n"; }
bad() { echo . >> "$tmp/f"; echo "FAIL: $*"; }
Z=0000000000000000000000000000000000000000

# --- classify.sh on a hand-made `git diff --raw -z` stream -----------------------------------------------------------------------------------------
rec() { printf ':%s %s %s %s %s\0%s\0' "$2" "$3" "$Z" "$Z" "$1" "$4"; } # rec <status> <oldmode> <newmode> <path>
A() { rec A 000000 100644 "$1"; }
M() { rec M 100644 100644 "$1"; }
D() { rec D 100644 000000 "$1"; }
cl() { # cl <expected first words> <description>; stdin = stream
  local want="$1" desc="$2" got; got="$("$here/classify.sh")"; ok
  [ "$got" = "$want" ] || bad "classify: $desc: want '$want', got '$got'"
}
cla() { # expects "all ..." (any reason)
  local desc="$1" got; got="$("$here/classify.sh")"; ok
  case "$got" in "all "*) ;; *) bad "classify: $desc: want 'all ...', got '$got'" ;; esac
}
{ M README.md; M docs/architecture.md; A docs/runbooks/new.md; } | cl "skip docs 3" "docs only"
{ M docs/images/arch-a.png; D docs/zh/x.md; M README.zh-CN.md; M CONTRIBUTING.md; M DESIGN_SCALE.md; } | cl "skip docs 5" "docs: png, zh, root files"
{ M deploy/helm/qv-business/values.yaml; A ci/helm/new_test.go; M ci/kind/cluster.yaml; } | cl "skip chart 3" "chart only"
{ M deploy/helm/qv-certs/catalog.json; } | cla "qv-certs catalog.json (read by internal/pki)"
{ M deploy/helm/qv-certs/values.yaml; } | cla "qv-certs chart (not listed)"
{ A deploy/helm/qv-newchart/Chart.yaml; } | cla "a new chart (not listed until checked)"
{ M docs/a.md; M deploy/helm/qv-party/Chart.yaml; } | cl "skip docs+chart 2" "docs and chart"
{ D docs/gone.md; } | cl "skip docs 1" "deleting a doc"
{ M docs/a.md; M internal/x/x.go; } | cla "docs plus one Go file"
{ M docs/a.md; M go.mod; } | cla "docs plus go.mod"
{ M docs/a.md; A newtopdir/readme.md; } | cla "a new unknown top-level directory"
{ A newtopdir/readme.md; } | cla "only a new unknown directory"
{ M docs/images/build.py; } | cla "docs/images/build.py (a script, not listed)"
{ M docs/a.txt; } | cla "docs/ with an unlisted extension"
{ M docs/a.MD; } | cla "case differs (.MD)"
{ M Docs/a.md; } | cla "case differs (Docs/)"
{ M readme.md; } | cla "case differs (readme.md)"
{ M deploy/postgres/signing_roles.sql; } | cla "deploy/postgres"
{ M deploy/keycloak/quorumvault-realm.json; } | cla "deploy/keycloak"
{ M deploy/redpanda/start.sh; } | cla "deploy/redpanda"
{ M deploy/temporal-gate/nginx.conf; } | cla "deploy/temporal-gate"
{ M deploy/images/README.md; } | cla "deploy/images/README.md (read by ci/helm)"
{ M deploy/images/contract.json; } | cla "deploy/images/contract.json"
{ M .github/workflows/ci.yml; } | cla ".github workflow"
{ M .github/workflows/helm.yml; } | cla ".github other workflow"
{ M .github/actions/mpc-env/action.yml; } | cla ".github action"
{ M ci/changes.sh; } | cla "the classifier itself"
{ M ci/classify.sh; } | cla "the classifier itself (2)"
{ M ci/skip-allowlist; } | cla "the allowlist"
{ M ci/changes_test.sh; } | cla "the classifier test"
{ M ci/README.md; } | cla "ci/README.md (ci/** is not on the list)"
{ M ci/run-in-image.sh; } | cla "ci script"
{ M ci/solana/Dockerfile; } | cla "ci image input"
{ M Makefile; } | cla "Makefile"
{ M go.sum; } | cla "go.sum"
{ M docker-compose.yml; } | cla "compose"
{ M scripts/pki.sh; } | cla "scripts"
{ M monitoring/prometheus.yml; } | cla "monitoring"
{ M web/approval/app.js; } | cla "web"
{ M migrations/0001_x.sql; } | cla "migrations"
{ M mpc-party/README.md; } | cla "mpc-party README (not listed)"
{ M internal/gateway/testdata/store_v1.sql; } | cla "testdata"
{ M e2e/evm/x_test.go; } | cla "e2e test"
{ M .env.example; } | cla ".env.example"
{ M .gitignore; } | cla ".gitignore"
# a rename shows as a delete plus an add with --no-renames (the job's own listing): both ends are checked
{ D docs/a.md; A deploy/postgres/a.md; } | cla "rename safe -> unsafe"
{ D deploy/postgres/a.md; A docs/a.md; } | cla "rename unsafe -> safe"
{ D docs/a.md; A docs/b.md; } | cl "skip docs 2" "rename safe -> safe"
# modes and types
{ rec M 100644 100755 docs/a.md; } | cla "mode change (chmod +x)"
{ rec A 000000 100755 docs/run.md; } | cla "added executable"
{ rec A 000000 120000 docs/link.md; } | cla "added symlink"
{ rec M 100644 120000 docs/a.md; } | cla "regular file turned symlink"
{ rec M 120000 120000 docs/link.md; } | cla "changed symlink"
{ rec A 000000 160000 docs/sub; } | cla "added submodule"
{ rec M 160000 160000 docs/sub; } | cla "changed submodule"
{ rec T 100644 120000 docs/a.md; } | cla "type change"
{ rec U 100644 100644 docs/a.md; } | cla "unmerged"
{ rec C 100644 100644 docs/a.md; } | cla "copy status"
{ rec R 100644 100644 docs/a.md; } | cla "rename status (must not appear, must not skip)"
# paths that are not plain
{ M ""; } | cla "empty path"
{ M "/docs/a.md"; } | cla "absolute path"
{ M "docs/../go.mod"; } | cla "dot-dot path"
{ M "docs/./a.md"; } | cla "dot path"
{ M "docs//a.md"; } | cla "double slash"
{ M $'docs/a\nb.md'; } | cla "newline in path"
{ M $'docs/a\tb.md'; } | cla "tab in path"
{ M 'docs/a\b.md'; } | cla "backslash in path"
{ M "docs/*.md"; } | cl "skip docs 1" "a file literally named *.md under docs (the glob is only in the list)"
# streams that do not parse
printf '' | cla "empty change list"
printf 'docs/a.md\0' | cla "a path with no metadata"
printf ':100644 100644 %s %s M\0' "$Z" "$Z" | cla "truncated: metadata only"
printf 'garbage' | cla "garbage"
printf ':100644 100644 M\0docs/a.md\0' | cla "short metadata"
printf ':100644 100644 %s %s M extra\0docs/a.md\0' "$Z" "$Z" | cla "long metadata"
{ M docs/a.md; printf ':100644'; } | cla "truncated after a good record" # must not skip on a half record
{ for i in $(seq 1 1000); do M "docs/f$i.md"; done; } | cl "skip docs 1000" "exactly 1000 doc files"
{ for i in $(seq 1 1001); do M "docs/f$i.md"; done; } | cla "1001 doc files"
{ for i in $(seq 1 3000); do M "docs/f$i.md"; done; } | cla "3000 doc files"
{ for i in $(seq 1 3000); do M "docs/f$i.md"; done; M go.mod; } | cla "3000 doc files and go.mod"

# a broken allowlist is never a skip: classify.sh copied next to bad lists
mkdir -p "$tmp/bad"; cp "$here/classify.sh" "$tmp/bad/"
bl() { printf '%s\n' "$1" > "$tmp/bad/skip-allowlist"; { M docs/a.md; } | "$tmp/bad/classify.sh"; }
for l in 'docs *' 'docs *.md' 'docs /etc/*' 'docs ../*' 'other docs/*' 'docs' 'docs a b' ''; do
  got="$(bl "$l")"; ok; case "$got" in "all "*) ;; *) bad "bad allowlist '$l' gave '$got'" ;; esac
done
rm -f "$tmp/bad/skip-allowlist"; got="$({ M docs/a.md; } | "$tmp/bad/classify.sh")"; ok; case "$got" in "all "*) ;; *) bad "missing allowlist gave '$got'" ;; esac

# --- changes.sh on simulated pull request events ---------------------------------------------------------------------------------------------------
repo="$tmp/repo"; git init -q "$repo"
(
  cd "$repo" || exit 1
  git config user.email t@example.invalid; git config user.name t; git config commit.gpgsign false
  mkdir -p docs/images docs/runbooks deploy/helm/qv-business deploy/postgres deploy/images ci/helm ci/kind .github/workflows internal/x
  for f in README.md docs/a.md docs/images/build.py docs/images/x.png docs/runbooks/r.md deploy/helm/qv-business/Chart.yaml ci/helm/check.sh ci/kind/c.yaml \
           deploy/postgres/x deploy/images/README.md .github/workflows/ci.yml ci/changes.sh ci/skip-allowlist internal/x/x.go go.mod; do
    echo "$f" > "$f"
  done
  git add -A; git commit -qm base; git branch -M main
)
mainsha="$(git -C "$repo" rev-parse HEAD)"

# run <event> <expected "skip <class> <n>" | all> <description> <mutation in the repo> [--push-wrong-head | --ff]
pr() {
  local event="$1" want="$2" desc="$3" mut="$4" mode="${5:-}" out="$tmp/out" head
  git -C "$repo" checkout -q -f main; git -C "$repo" clean -fdq; git -C "$repo" branch -D pr -q 2>/dev/null
  git -C "$repo" checkout -q -b pr
  (cd "$repo" && eval "$mut")
  git -C "$repo" add -A; git -C "$repo" commit -q --allow-empty -m "${MSG:-change}" || { bad "$desc: commit failed"; return; }
  head="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q main
  if [ "$mode" = --ff ]; then git -C "$repo" merge -q --ff-only pr; else git -C "$repo" merge -q --no-ff -m merge pr; fi
  [ "$mode" = --push-wrong-head ] && head="$mainsha"
  rm -f "$out"; : > "$out"
  (cd "$repo" && QV_EVENT_NAME="$event" QV_PR_HEAD_SHA="$head" GITHUB_OUTPUT="$out" "$here/changes.sh" > "$tmp/log" 2>&1); local rc=$?
  check_out "$want" "$desc" "$out" "$rc"
  git -C "$repo" checkout -q -f main; git -C "$repo" reset -q --hard "$mainsha"
}
check_out() { # check_out <want> <desc> <outfile> <rc>
  local want="$1" desc="$2" out="$3" rc="$4" skip class count
  ok
  [ "$rc" = 0 ] || { bad "changes.sh: $desc: exit code $rc ($(cat "$tmp/log"))"; return; }
  skip="$(sed -n 's/^skip=//p' "$out")"; class="$(sed -n 's/^class=//p' "$out")"; count="$(sed -n 's/^count=//p' "$out")"
  if [ "$want" = all ]; then
    [ "$skip" = false ] || bad "changes.sh: $desc: want skip=false, got '$skip' ($(cat "$tmp/log"))"
  else
    [ "$skip" = true ] && [ "$want" = "skip $class $count" ] || bad "changes.sh: $desc: want '$want', got skip=$skip class=$class count=$count"
  fi
  [ "$(grep -c '^skip=' "$out")" = 1 ] || bad "changes.sh: $desc: skip must be written exactly once"
}

pr pull_request "skip docs 2" "docs only" 'echo x >> README.md; echo x >> docs/a.md'
pr pull_request "skip chart 3" "chart only" 'echo x >> deploy/helm/qv-business/Chart.yaml; echo x >> ci/helm/check.sh; echo x >> ci/kind/c.yaml'
pr pull_request "skip docs+chart 2" "docs and chart" 'echo x >> README.md; echo x >> ci/helm/check.sh'
pr pull_request "skip docs 1" "docs deletion" 'git rm -q docs/a.md'
pr pull_request "skip docs 2" "docs rename inside docs" 'git mv docs/a.md docs/b.md'
pr pull_request all "docs plus one Go file" 'echo x >> README.md; echo x >> internal/x/x.go'
pr pull_request all "go file deletion" 'git rm -q internal/x/x.go'
pr pull_request all "new unknown top-level directory" 'mkdir newdir; echo x > newdir/y.md'
pr pull_request all "rename safe -> unsafe" 'git mv docs/a.md deploy/postgres/a.md'
pr pull_request all "rename unsafe -> safe" 'git mv deploy/postgres/x docs/x.md'
pr pull_request all "file under .github" 'echo x >> .github/workflows/ci.yml'
pr pull_request all "deploy/postgres" 'echo x >> deploy/postgres/x'
pr pull_request all "deploy/images/README.md" 'echo x >> deploy/images/README.md'
pr pull_request all "docs/images/build.py" 'echo x >> docs/images/build.py'
pr pull_request "skip docs 1" "docs/images png" 'echo x >> docs/images/x.png'
pr pull_request all "the classifier" 'echo x >> ci/changes.sh'
pr pull_request all "the allowlist" 'echo "docs *" >> ci/skip-allowlist'
pr pull_request all "empty change list" 'true'
pr pull_request all "chmod +x on a doc" 'chmod +x README.md'
pr pull_request all "symlink in docs" 'ln -s ../go.mod docs/link.md'
pr pull_request all "submodule in docs" 'git update-index --add --cacheinfo 160000,'"$mainsha"',docs/sub'
pr push all "push event, docs only" 'echo x >> README.md'
pr workflow_dispatch all "dispatch event, docs only" 'echo x >> README.md'
pr merge_group all "merge queue event, docs only" 'echo x >> README.md'
pr schedule all "schedule event, docs only" 'echo x >> README.md'
pr "" all "no event name, docs only" 'echo x >> README.md'
pr pull_request all "head sha is not the merge commit's second parent" 'echo x >> README.md' --push-wrong-head
pr pull_request all "HEAD is not a merge commit (fast-forward)" 'echo x >> README.md' --ff
MSG="docs only, but [ci full]" pr pull_request all "commit message asks for a full run" 'echo x >> README.md'
MSG="docs fix" pr pull_request "skip docs 1" "commit message without the token" 'echo x >> README.md'
pr pull_request all "1001 doc files" 'for i in $(seq 1 1001); do echo x > docs/g$i.md; done'
pr pull_request all "3000 doc files" 'for i in $(seq 1 3000); do echo x > docs/g$i.md; done'

# errors of the lister and of the environment
run_in() { # run_in <dir> [env...]: runs changes.sh there, with the env given; leaves the output file in $tmp/out
  local d="$1"; shift; : > "$tmp/out"
  (cd "$d" && env "$@" GITHUB_OUTPUT="$tmp/out" "$here/changes.sh" > "$tmp/log" 2>&1); echo $?
}
mkdir -p "$tmp/norepo"
rc="$(run_in "$tmp/norepo" QV_EVENT_NAME=pull_request QV_PR_HEAD_SHA=abc)"; check_out all "not a git repository" "$tmp/out" "$rc"
git -C "$repo" checkout -q -f main
git clone -q --depth 1 "file://$repo" "$tmp/shallow"
rc="$(run_in "$tmp/shallow" QV_EVENT_NAME=pull_request QV_PR_HEAD_SHA="$mainsha")"; check_out all "shallow clone, one commit" "$tmp/out" "$rc"
rc="$(run_in "$repo" QV_EVENT_NAME=pull_request)"; check_out all "no head sha" "$tmp/out" "$rc"
# a classifier that crashes, prints two lines, prints something else, or is missing: never a skip
git -C "$repo" checkout -q -b pr2; echo x >> "$repo/README.md"; git -C "$repo" commit -qam docs; h2="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q main; git -C "$repo" merge -q --no-ff -m merge pr2
for fake in 'exit 3' 'echo "skip docs 5"; echo "skip docs 6"' 'echo "skip other 5"' 'echo "skip docs five"' 'echo skip' 'echo "skip docs 1 extra"' 'true' 'kill -9 $$'; do
  rm -rf "$tmp/fakeci"; mkdir "$tmp/fakeci"; cp "$here/changes.sh" "$tmp/fakeci/"; printf '#!/usr/bin/env bash\n%s\n' "$fake" > "$tmp/fakeci/classify.sh"; chmod +x "$tmp/fakeci/"*
  : > "$tmp/out"; (cd "$repo" && QV_EVENT_NAME=pull_request QV_PR_HEAD_SHA="$h2" GITHUB_OUTPUT="$tmp/out" "$tmp/fakeci/changes.sh" > "$tmp/log" 2>&1); rc=$?
  check_out all "classifier that does: $fake" "$tmp/out" "$rc"
done
rm -f "$tmp/fakeci/classify.sh"; : > "$tmp/out"; (cd "$repo" && QV_EVENT_NAME=pull_request QV_PR_HEAD_SHA="$h2" GITHUB_OUTPUT="$tmp/out" "$tmp/fakeci/changes.sh" > "$tmp/log" 2>&1); rc=$?
check_out all "classifier missing" "$tmp/out" "$rc"
# sanity: the same event with the real classifier does skip
: > "$tmp/out"; (cd "$repo" && QV_EVENT_NAME=pull_request QV_PR_HEAD_SHA="$h2" GITHUB_OUTPUT="$tmp/out" "$here/changes.sh" > "$tmp/log" 2>&1); rc=$?
check_out "skip docs 1" "control: the real classifier on the same event" "$tmp/out" "$rc"
# the log line and the summary say what was skipped
grep -q 'skipped: documentation-only change (1 files' "$tmp/log" || bad "the log does not say 'skipped: documentation-only change'"; ok

# the workflow keeps its side of the bargain (a text check; the full run on a real pull request is the proof)
wf="$here/../.github/workflows/ci.yml"
chk() { ok; grep -qF -- "$1" "$wf" || bad "ci.yml: $2"; }
chk "if: \${{ !cancelled() && needs.changes.outputs.skip != 'true' }}" "the image job must run unless skip is exactly 'true' (and run when changes failed)"
chk "if: \${{ !cancelled() }}" "the test job must run even when changes failed"
chk "continue-on-error: true" "the classify step must not fail the job"
chk "run: ci/changes.sh" "ci.yml does not run ci/changes.sh"
chk "ci/skip-guard.sh" "ci.yml does not run the guard"
ok; ! grep -qE "skip *== *'false'|skip *!= *'false'" "$wf" || bad "ci.yml compares skip with 'false': only the exact value true may skip"
n_steps="$(awk '/^  test:/{t=1} /^  # cb-mpc wrapper/{t=0} t&&/^      - /{n++} END{print n}' "$wf")"
n_if="$(awk '/^  test:/{t=1} /^  # cb-mpc wrapper/{t=0} t&&/^        if: \$\{\{ needs.changes.outputs.skip/{c++} END{print c}' "$wf")"
ok; [ "$n_steps" = "$n_if" ] || bad "ci.yml: every step of the test job needs the skip condition ($n_steps steps, $n_if conditions)"

total="$(wc -l < "$tmp/n" | tr -d ' ')"; fails="$(wc -l < "$tmp/f" | tr -d ' ')"
echo "changes_test: $((total - fails))/$total checks passed"
[ "$fails" = 0 ] && [ "$total" -gt 100 ]
