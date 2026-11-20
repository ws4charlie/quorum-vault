#!/usr/bin/env bash
# Tests of ci/skip-guard.sh in a scratch repository: a reader of an allowlisted path must fail the guard, harmless mentions and reviewed exceptions must not.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fails=0; total=0
r="$tmp/r"; git init -q "$r"; mkdir -p "$r/ci" "$r/.github/workflows"
cp "$here/skip-guard.sh" "$here/skip-allowlist" "$r/ci/"; : > "$r/ci/skip-guard-exceptions"
echo 'name: ci' > "$r/.github/workflows/ci.yml"
git -C "$r" -c user.email=t@t -c user.name=t add -A >/dev/null; git -C "$r" -c user.email=t@t -c user.name=t commit -qm base

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
EXC='internal/x/a_test.go\t*\tchecked\n' case_ ok   "a reviewed exception" internal/x/a_test.go 'const p = "docs/x.md"'
EXC='internal/x/a_test.go\tdocs/\tchecked\n' case_ fail "an exception for another needle" internal/x/a_test.go 'b, _ := os.ReadFile("../../README.md")'
EXC='internal/gone/a_test.go\tdocs/\tnobody reads it\n' case_ fail "a stale exception (no reader left)" x/none.txt 'nothing'
EXC='x/none.txt\t*\tnothing\n' case_ fail "a stale wildcard exception" x/none.txt 'nothing'

# the real repository passes, and the guard really looks at it
total=$((total + 1)); (cd "$here/.." && ci/skip-guard.sh >/dev/null 2>&1) || { fails=$((fails + 1)); echo "FAIL: the repository itself does not pass the guard"; (cd "$here/.." && ci/skip-guard.sh | head); }
echo "skip-guard_test: $((total - fails))/$total checks passed"
[ "$fails" = 0 ]
