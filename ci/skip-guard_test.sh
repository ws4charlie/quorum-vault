#!/usr/bin/env bash
# Tests of ci/skip-guard.sh in a scratch repository: a reader of an allowlisted path must fail the guard, harmless mentions and reviewed exceptions must not.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fails=0; total=0
r="$tmp/r"; git init -q "$r"; mkdir -p "$r/ci" "$r/.github/workflows"
cp "$here/skip-guard.sh" "$here/skip-allowlist" "$here/skip-module-exceptions" "$r/ci/"; : > "$r/ci/skip-guard-exceptions"
echo 'name: ci' > "$r/.github/workflows/ci.yml"
# one tracked file per allowlist pattern (the guard refuses a pattern that matches nothing), the root module, and the reviewed own module ci/helm
while IFS= read -r l; do
  case "$l" in ''|'#'*) continue ;; esac
  read -r _ p _ <<<"$l"; f="${p//\*/x}"; mkdir -p "$r/$(dirname "$f")"; echo seed > "$r/$f"
done < "$here/skip-allowlist"
# the workflows that test the chart paths on pull requests (the guard checks their filters)
printf 'on:\n  pull_request:\n    paths: ["deploy/**", "ci/**"]\n' > "$r/.github/workflows/helm.yml"
printf 'on:\n  pull_request:\n    paths: ["deploy/**", "ci/kind/**"]\n' > "$r/.github/workflows/kind.yml"
printf 'module root\n' > "$r/go.mod"; printf 'module helmcheck\n' > "$r/ci/helm/go.mod"
mkdir -p "$r/internal/real"; echo 'package real' > "$r/internal/real/real.go"
git -C "$r" -c user.email=t@t -c user.name=t add -A >/dev/null; git -C "$r" -c user.email=t@t -c user.name=t commit -qm base

# more than one file: with_files <ok|fail> <description> <file> <content> [<file> <content>]...   (ALLOW: a replacement ci/skip-allowlist; RM: files to delete)
with_files() {
  local want="$1" desc="$2" out rc f; shift 2; local made=()
  while [ $# -ge 2 ]; do mkdir -p "$(dirname "$r/$1")"; printf '%s\n' "$2" > "$r/$1"; made+=("$1"); shift 2; done
  [ -z "${ALLOW:-}" ] || { cp "$r/ci/skip-allowlist" "$tmp/allow.keep"; printf '%b' "$ALLOW" > "$r/ci/skip-allowlist"; }
  for f in ${RM:-}; do mv "$r/$f" "$tmp/rm.$(basename "$f")"; done
  git -C "$r" add -A; out="$(cd "$r" && ci/skip-guard.sh 2>&1)"; rc=$?
  total=$((total + 1))
  if [ "$want" = ok ] && [ "$rc" != 0 ]; then fails=$((fails + 1)); echo "FAIL: $desc: guard failed: $out"; fi
  if [ "$want" = fail ] && [ "$rc" = 0 ]; then fails=$((fails + 1)); echo "FAIL: $desc: guard passed but must fail"; fi
  for f in ${RM:-}; do mv "$tmp/rm.$(basename "$f")" "$r/$f"; done
  [ -z "${ALLOW:-}" ] || cp "$tmp/allow.keep" "$r/ci/skip-allowlist"
  for f in "${made[@]}"; do git -C "$r" rm -q -f --cached "$f" >/dev/null 2>&1; rm -f "$r/$f"; done
  git -C "$r" add -A; ALLOW=""; RM=""
}
# case <expect ok|fail> <description> <file> <content>   (exceptions: EXC env)
case_() {
  local want="$1" desc="$2" file="$3" content="$4" out rc
  mkdir -p "$(dirname "$r/$file")"; printf '%s\n' "$content" > "$r/$file"; printf '%b' "${EXC:-}" > "$r/ci/skip-guard-exceptions"
  git -C "$r" add -A; out="$(cd "$r" && ci/skip-guard.sh 2>&1)"; rc=$?
  total=$((total + 1))
  if [ "$want" = ok ] && [ "$rc" != 0 ]; then fails=$((fails + 1)); echo "FAIL: $desc: guard failed: $out"; fi
  if [ "$want" = fail ] && [ "$rc" = 0 ]; then fails=$((fails + 1)); echo "FAIL: $desc: guard passed but must fail"; fi
  git -C "$r" rm -q -f --cached "$file" >/dev/null; rm -f "$r/$file"; : > "$r/ci/skip-guard-exceptions"; EXC=""
}
case_ ok   "clean repository" x/none.txt "nothing"
case_ fail "Go test reads a doc" internal/x/a_test.go 'b, _ := os.ReadFile("../../docs/architecture.md")'
case_ fail "Go test reads a doc through a constant" internal/x/a_test.go 'const doc = "docs/runbooks/x.md"'
case_ fail "Go test reads a README" internal/x/a_test.go 'os.ReadFile("../../README.md")'
case_ fail "Go test joins path segments to a chart" internal/x/a_test.go 'p := filepath.Join("..", "..", "deploy", "helm", "qv-business")'
case_ fail "Go test reads the business chart" internal/x/a_test.go 'p := "../../deploy/helm/qv-business/values.yaml"'
case_ fail "Go test joins segments to docs" internal/x/a_test.go 'p := filepath.Join(root, "docs", "runbooks")'
case_ fail "Go test reads a png" internal/x/a_test.go 'os.Open("fig.png")'
case_ fail "shell script cats a doc" scripts/x.sh 'cat docs/runbooks/x.md'
case_ fail "shell script greps a README" scripts/x.sh 'grep -q foo CONTRIBUTING.md'
case_ fail "Makefile runs a chart check" Makefile $'x:\n\tci/helm/check.sh'
case_ fail "compose mounts docs" docker-compose.yml '    volumes: ["./docs:/docs"]'
case_ fail "workflow reads the chart" .github/workflows/other.yml '        run: helm lint deploy/helm/qv-business'
case_ fail "ci.yml calls the chart check" .github/workflows/ci.yml '      - run: make helm-check'
echo 'name: ci' > "$r/.github/workflows/ci.yml"; git -C "$r" add -A
case_ fail "embed of a markdown" internal/x/e.go '//go:embed notes.md'
case_ ok   "a Go comment that names a doc" internal/x/a.go '// see docs/runbooks/x.md'
case_ ok   "an error message that names a doc" internal/x/a.go 'return fmt.Errorf("zone is behind (docs/runbooks/key-replacement.md)")'
case_ ok   "a log message that names a doc" internal/x/a.go 'log.Error("ALERT: look at the runbook (docs/runbooks/btc-fee-caps.md)", "id", id)'
case_ ok   "a shell echo that names a doc" scripts/x.sh 'echo "see docs/runbooks/x.md"'
case_ ok   "a Markdown file that names a doc (not a reader)" notes/x.md 'see docs/runbooks/x.md and README.md'
case_ ok   "a JSON file that names a doc (data)" config/x.json '{"c": "docs/x.md"}'
case_ ok   "a path outside the list" internal/x/a_test.go 'os.ReadFile("../../docker-compose.yml")'
EXC='internal/x/a_test.go\t1\tdocs/x.md\tchecked\n' case_ ok   "a reviewed exception (the exact line)" internal/x/a_test.go 'const p = "docs/x.md"'
EXC='internal/x/a_test.go\t1\tdocs/x.md\tchecked\n' case_ fail "an exception for other text" internal/x/a_test.go 'b, _ := os.ReadFile("../../README.md")'
EXC='internal/gone/a_test.go\t1\tdocs/\tnobody reads it\n' case_ fail "a stale exception (no reader left)" x/none.txt 'nothing'
EXC='x/none.txt\t1\t*\tnothing\n' case_ fail "a stale wildcard exception" x/none.txt 'nothing'

# the allowlist against the tree (fix1): empty patterns, executable kinds, module boundaries, the reviewed own-module exception
with_files ok   "baseline: seeds, root module, ci/helm as an own module" x/none.txt nothing
ALLOW='docs docs/*.md\nchart ci/kind/*\n' with_files fail "a pattern for a tree that is not in the repository (ci/kind/*)" x/none.txt nothing
ALLOW='docs docs/*.md\ndocs docs/*.png\ndocs docs/*.txt\n' with_files fail "a pattern that matches no tracked file" x/none.txt nothing
with_files fail ".go under an allowlisted chart" deploy/helm/qv-business/tool.go 'package main'
with_files fail ".sh under an allowlisted chart" deploy/helm/qv-business/check.sh '#!/bin/sh'
with_files fail "go.mod under an allowlisted chart (an own module with no reviewed exception)" deploy/helm/qv-party/go.mod 'module x' deploy/helm/qv-party/tool.go 'package main'
with_files fail "Makefile under an allowlisted chart" deploy/helm/qv-business/Makefile 'all:'
with_files fail "Dockerfile under an allowlisted chart" deploy/helm/qv-business/Dockerfile 'FROM x'
with_files fail ".sql under an allowlisted chart" deploy/helm/qv-business/q.sql 'select 1;'
with_files fail "a root-module Go package next to a doc (the mkbucket mistake, on a docs path)" docs/pkg/main.go 'package main' docs/pkg/notes.md 'x'
with_files fail "a Go file in docs/ itself (docs/*.png sits in the package directory)" docs/z.go 'package docs'
with_files fail "a doc below a root-module Go package directory (go:embed can reach it)" docs/pkg/main.go 'package main' docs/pkg/sub/deep.png 'x'
with_files ok   "a doc next to an own module that ci.yml does not enter" docs/tools/go.mod 'module t' docs/tools/main.go 'package main' docs/tools/README.md 'x'
with_files ok   "ci/helm keeps Go and shell files (reviewed own module)" ci/helm/x_test.go 'package helmcheck' ci/helm/new.sh '#!/bin/sh'
with_files fail "the reviewed tree is entered by ci.yml" .github/workflows/ci.yml '      - run: cd ci/helm && go test ./...'
echo 'name: ci' > "$r/.github/workflows/ci.yml"; git -C "$r" add -A
RM=ci/helm/go.mod with_files fail "the reviewed tree has no go.mod: it is not a module" x/none.txt nothing
with_files fail "a make target that ci.yml calls enters the reviewed tree" Makefile $'all:\n\tcd ci/helm && go test ./...' .github/workflows/ci.yml '      - run: make all'
echo 'name: ci' > "$r/.github/workflows/ci.yml"; git -C "$r" rm -q -f --cached Makefile >/dev/null 2>&1; rm -f "$r/Makefile"; git -C "$r" add -A
printf 'Makefile\t1\tci/helm/check.sh\treviewed\n' > "$r/ci/skip-guard-exceptions"
with_files ok   "a make target that ci.yml does not call may name ci/helm (reviewed as a reader)" Makefile $'helm-check:\n\tci/helm/check.sh'
: > "$r/ci/skip-guard-exceptions"

# fix2: an exception names the exact reviewed occurrence; a new reader in an excepted file is not hidden
X='internal/pki/catalog_chart_test.go'; L='const chartCatalog = "../../deploy/helm/qv-certs/catalog.json"'
printf '%s\t1\t../../deploy/helm/qv-certs/catalog.json\treviewed\n' "$X" > "$r/ci/skip-guard-exceptions"
with_files ok   "the excepted file with exactly the reviewed line" "$X" "$L"
with_files fail "the excepted file gains a documentation read" "$X" "$L"$'\n''b, _ := os.ReadFile("../../docs/architecture.md")'
with_files fail "the excepted file gains a README read" "$X" "$L"$'\n''os.ReadFile("../../README.md")'
with_files fail "the excepted file gains a second chart read (count exceeded)" "$X" "$L"$'\n''const other = "../../deploy/helm/qv-certs/catalog.json"'
with_files fail "the reviewed line changed" "$X" 'const chartCatalog = "../../deploy/helm/qv-business/values.yaml"'
with_files fail "the reviewed line vanished (the exception is stale)" "$X" 'package x'
printf '%s\t6\t*\twhole file, bounded\n' ".github/workflows/helm.yml" > "$r/ci/skip-guard-exceptions"
six=$'on:\n  pull_request:\n    paths:\n      - "deploy/helm/**"\n      - "ci/helm/**"\n      - "deploy/images/README.md"\n  x: ci/helm/go.mod\n  y: ci/helm/go.sum\n  run: ci/helm/check.sh'
with_files ok   "a whole-file exception with the reviewed count" .github/workflows/helm.yml "$six"
with_files fail "a whole-file exception: a seventh line" .github/workflows/helm.yml "$six"$'\n  also: deploy/helm/qv-business'
: > "$r/ci/skip-guard-exceptions"
printf 'x\tmany\ttext\treason\n' > "$r/ci/skip-guard-exceptions"
with_files fail "an exception line with no number" x/none.txt nothing
: > "$r/ci/skip-guard-exceptions"

# fix4: the skip is safe only while helm.yml and kind.yml run on chart changes
printf 'on:\n  pull_request:\n    paths: ["deploy/**", "ci/**"]\n' > "$r/.github/workflows/helm.yml"; git -C "$r" add -A   # an earlier case replaced it
wf() { # wf <ok|fail> <description> <workflow file name> <content>: replaces the fixture workflow for one check
  local want="$1" desc="$2" f="$r/.github/workflows/$3" out rc; cp "$f" "$tmp/wf.keep"; printf '%b' "$4" > "$f"; git -C "$r" add -A
  out="$(cd "$r" && ci/skip-guard.sh 2>&1)"; rc=$?; total=$((total + 1))
  if [ "$want" = ok ] && [ "$rc" != 0 ]; then fails=$((fails + 1)); echo "FAIL: $desc: guard failed: $out"; fi
  if [ "$want" = fail ] && [ "$rc" = 0 ]; then fails=$((fails + 1)); echo "FAIL: $desc: guard passed but must fail"; fi
  cp "$tmp/wf.keep" "$f"; git -C "$r" add -A
}
wf fail "helm.yml stops covering ci/helm"            helm.yml 'on:\n  pull_request:\n    paths: ["deploy/**"]\n'
wf fail "helm.yml stops covering deploy/helm"        helm.yml 'on:\n  pull_request:\n    paths: ["ci/**"]\n'
wf fail "helm.yml loses its paths (runs on none)"    helm.yml 'on:\n  workflow_dispatch:\n'
wf fail "helm.yml uses paths-ignore"                 helm.yml 'on:\n  pull_request:\n    paths-ignore: ["docs/**"]\n'
wf fail "kind.yml stops covering the charts"         kind.yml 'on:\n  pull_request:\n    paths: ["ci/kind/**"]\n'
wf fail "kind.yml covers only one chart"             kind.yml 'on:\n  pull_request:\n    paths: ["deploy/helm/qv-business/**"]\n'
wf ok   "block-list paths that cover the charts"     kind.yml 'on:\n  pull_request:\n    paths:\n      - "deploy/**"   # comment\n      - ci/kind/**\n'
wf ok   "a single * does not cross /, ** does"       helm.yml 'on:\n  pull_request:\n    paths: ["deploy/**", "ci/*/*"]\n'
wf fail "a single * does not cross /"                helm.yml 'on:\n  pull_request:\n    paths: ["deploy/*", "ci/*"]\n'
rm -f "$r/.github/workflows/kind.yml"; git -C "$r" add -A; out="$(cd "$r" && ci/skip-guard.sh 2>&1)"; rc=$?; total=$((total + 1)); [ "$rc" != 0 ] || { fails=$((fails + 1)); echo "FAIL: guard passed without kind.yml"; }
printf 'on:\n  pull_request:\n    paths: ["deploy/**", "ci/kind/**"]\n' > "$r/.github/workflows/kind.yml"; git -C "$r" add -A

# the real repository passes, and the guard really looks at it
total=$((total + 1)); (cd "$here/.." && ci/skip-guard.sh >/dev/null 2>&1) || { fails=$((fails + 1)); echo "FAIL: the repository itself does not pass the guard"; (cd "$here/.." && ci/skip-guard.sh | head); }
echo "skip-guard_test: $((total - fails))/$total checks passed"
[ "$fails" = 0 ]
