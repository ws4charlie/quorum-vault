#!/usr/bin/env bash
# Guard against the allowlist (ci/skip-allowlist) rotting: fails when a file that is NOT on the allowlist (code, script, Makefile, compose file, Dockerfile,
# workflow, test) names a path or file type that IS on it, so that a test or script which starts reading docs/**, a README or a chart makes whoever adds it
# shrink the allowlist (or explain why the reader is harmless, in ci/skip-guard-exceptions). Runs in the `changes` job, in a git checkout.
#
# What counts as a reader: any line of a tracked, non-allowlisted file that contains a needle taken from the allowlist (the literal start of each
# pattern, its literal end after the last `*`, and for a directory the Go form "a", "b"), unless the line is a comment, or an error/log message
# that opens no file. A line that mixes a needle with a file-access call is always a hit. Over-reporting is the point: better a reviewed exception
# than a skipped job that should have run.
# Usage: ci/skip-guard.sh   (exit 1 and the hits on failure)
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$(git -C "$here" rev-parse --show-toplevel)" || exit 2
allow="$here/skip-allowlist"; exc="${QV_SKIP_GUARD_EXCEPTIONS:-$here/skip-guard-exceptions}"

pats=(); needles=(); regexes=()
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ''|'#'*) continue ;; esac
  read -r _ p _ <<<"$line"; pats+=("$p")
  pre="${p%%\**}"; [ -n "$pre" ] && needles+=("$pre")
  case "$p" in *\**) suf="${p##*\*}"; [ -n "$suf" ] && needles+=("$suf") ;; esac
  case "$pre" in */) # a directory: the path with and without the slash, its parent when that has two segments, the Go form "deploy", "helm", the bare name of a top-level one
    dir="${pre%/}"; needles+=("$dir")
    case "$dir" in */*/*) par="${dir%/*}"; needles+=("$par"); segs="$par" ;; */*) segs="$dir" ;; *) segs="" ;; esac
    if [ -n "$segs" ]; then regexes+=("\"$(printf '%s' "$segs" | sed 's#/#"[[:space:]]*,[[:space:]]*"#g')\""); else regexes+=("(^|[^A-Za-z0-9_-])$dir([^A-Za-z0-9_-]|$)"); fi
    case "$dir" in */*) regexes+=("\"$(printf '%s' "$dir" | sed 's#/#"[[:space:]]*,[[:space:]]*"#g')\"") ;; esac ;;
  esac
done < "$allow"
[ "${#pats[@]}" -gt 0 ] || { echo "skip-guard: empty allowlist"; exit 2; }

# ---- the allowlist against the tree (every run) -------------------------------------------------------------------------------------------------------
bad=0
tracked="$(mktemp)"; allowed="$(mktemp)"; corpus="$(mktemp)"; godirs="$(mktemp)"
git ls-files > "$tracked"
matches() { # matches <path>: is it on the allowlist?
  local f="$1" p
  for p in "${pats[@]}"; do
    # shellcheck disable=SC2254
    case "$f" in $p) return 0 ;; esac
  done
  return 1
}
# 1. no pre-approval of trees that do not exist: every pattern must match a tracked file
for p in "${pats[@]}"; do
  found=0
  while IFS= read -r f; do
    # shellcheck disable=SC2254
    case "$f" in $p) found=1; break ;; esac
  done < "$tracked"
  [ "$found" = 1 ] || { bad=1; echo "EMPTY pattern: '$p' of ci/skip-allowlist matches no tracked file. A pattern for files that are not in the repository cannot be proven safe: remove it, and add it in the pull request that brings the files."; }
done
while IFS= read -r f; do matches "$f" && printf '%s\n' "$f"; done < "$tracked" > "$allowed"

# reviewed own-module trees (ci/skip-module-exceptions): <tree/><TAB><reason>
modexc="$here/skip-module-exceptions"; trees=()
if [ -r "$modexc" ]; then
  while IFS=$'\t' read -r t _ || [ -n "$t" ]; do
    case "$t" in ''|'#'*) continue ;; */) trees+=("$t") ;; *) bad=1; echo "BAD module exception '$t': it must be a directory ending in /" ;; esac
  done < "$modexc"
fi

# nearest Go module directory of a tracked path ("." = the root module); empty when there is none
nearest_module() {
  local d; d="$(dirname "$1")"
  while :; do
    if [ "$d" = . ]; then grep -qxF go.mod "$tracked" && echo . ; return; fi
    if grep -qxF "$d/go.mod" "$tracked"; then echo "$d"; return; fi
    d="$(dirname "$d")"
  done
}
# the Go modules that ci.yml builds or tests: the root, and every module directory named by ci.yml, .github/actions, the make targets they call (with their
# prerequisites) and the scripts those name. Found from the files, not listed here.
cat .github/workflows/ci.yml .github/actions/*/action.yml 2>/dev/null > "$corpus"
targets="$(grep -ohE 'make +[A-Za-z0-9_.-]+' "$corpus" | awk '{print $2}' | sort -u | tr '\n' ' ')"
if [ -r Makefile ] && [ -n "$targets" ]; then
  awk -v roots="$targets" '
    BEGIN { n = split(roots, r, " "); for (i = 1; i <= n; i++) want[r[i]] = 1 }
    /^[A-Za-z0-9_.-]+:/ && !/^\./ { t = $0; sub(/:.*/, "", t); cur = t; pre = $0; sub(/^[^:]*:/, "", pre); sub(/#.*/, "", pre); prereq[t] = pre; next }
    /^\t/ { if (cur != "") recipe[cur] = recipe[cur] "\n" $0; next }
    /^[^\t]/ { cur = "" }
    END {
      do { changed = 0
        for (t in want) { m = split(prereq[t], ps, " "); for (j = 1; j <= m; j++) if (!(ps[j] in want) && ps[j] in prereq) { want[ps[j]] = 1; changed = 1 } }
      } while (changed)
      for (t in want) print recipe[t]
    }' Makefile >> "$corpus"
fi
for _ in 1 2 3; do # scripts named in the corpus, then the scripts they name
  while IFS= read -r f; do
    case "$f" in ci/changes*.sh|ci/classify.sh|ci/skip-guard*.sh) continue ;; *.sh) grep -qF -- "$f" "$corpus" && cat "$f" >> "$corpus" ;; esac
  done < "$tracked"
done
grep -vE '^[[:space:]]*#' "$corpus" > "$corpus.nc" && mv "$corpus.nc" "$corpus"   # comments name things without running them
entered() { # entered <module dir>
  [ "$1" = . ] && return 0
  grep -qF -- "$1/" "$corpus" || grep -qE -- "cd +$1( |&|;|$)" "$corpus"
}
grep -E '\.go$' "$tracked" | while IFS= read -r f; do dirname "$f"; done | sort -u > "$godirs"

while IFS= read -r f; do
  # 2. an extension that a job compiles or runs: only inside a reviewed own-module tree that no ci.yml job enters
  case "${f##*/}" in
    *.go|go.mod|go.sum|*.sh|*.bash|*.py|*.sql|*.proto|*.mk|*.js|Makefile|Dockerfile*|*.Dockerfile)
      inside=""; for t in "${trees[@]+"${trees[@]}"}"; do case "$f" in "$t"*) inside="$t" ;; esac; done
      if [ -z "$inside" ]; then bad=1; echo "EXECUTABLE: $f is on the allowlist but a job compiles or runs files of this kind. Narrow the pattern."; continue; fi
      if ! grep -qxF "${inside}go.mod" "$tracked"; then bad=1; echo "EXCEPTION: $inside has no go.mod of its own: it is not a separate module"; continue; fi
      ;;
  esac
  # 3. module boundary: no allowlisted file may sit in a package directory (or below one) of a module that ci.yml builds or tests
  m="$(nearest_module "$f")"
  [ -n "$m" ] || continue
  entered "$m" || continue
  d="$(dirname "$f")"
  while :; do
    if grep -qxF "$d" "$godirs" && [ "$(nearest_module "$d/x")" = "$m" ]; then
      bad=1; echo "MODULE: $f is on the allowlist but lies in/under the Go package directory $d of the module '$m', which ci.yml builds or tests (go:embed, testdata, a build input). Narrow the pattern."; break
    fi
    [ "$d" = "$m" ] && break
    [ "$d" = . ] && break
    d="$(dirname "$d")"
  done
done < "$allowed"
# a reviewed tree must really be a module that ci.yml does not enter
for t in "${trees[@]+"${trees[@]}"}"; do
  grep -qxF "${t}go.mod" "$tracked" || { bad=1; echo "EXCEPTION: ${t} has no go.mod of its own: it is not a separate module"; }
  if entered "${t%/}"; then bad=1; echo "EXCEPTION: ci.yml (or something it calls) names ${t%/}: the module is run by a ci.yml job, so ${t} cannot be skipped"; fi
done
rm -f "$tracked" "$allowed" "$corpus" "$godirs"

# the files to read: tracked, not on the allowlist, not the machinery of this guard
files="$(mktemp)"; hits="$(mktemp)"; trap 'rm -f "$files" "$hits"' EXIT
git ls-files -z | while IFS= read -r -d '' f; do
  skip=0
  case "$f" in ci/changes.sh|ci/changes_test.sh|ci/classify.sh|ci/skip-allowlist|ci/skip-guard.sh|ci/skip-guard_test.sh|ci/skip-guard-exceptions|ci/skip-module-exceptions) skip=1 ;; esac
  for p in "${pats[@]}"; do
    # shellcheck disable=SC2254
    case "$f" in $p) skip=1 ;; esac
  done
  # only files that can open a file: code, scripts, Makefiles, compose files, Dockerfiles, workflows (docs, JSON, SQL, YAML rules, HTML are data)
  case "$f" in
    *.go|*.sh|*.bash|*.py|*.js|*.mk|Makefile|*/Makefile|*Dockerfile*|docker-compose*.yml|.github/*|go.mod) ;;
    *) skip=1 ;;
  esac
  [ "$skip" = 1 ] || printf '%s\0' "$f"
done > "$files"

: > "$hits"
if [ -s "$files" ]; then
  for n in "${needles[@]}"; do
    xargs -0 grep -HInF -e "$n" < "$files" 2>/dev/null | sed "s#^#F\t$n\t#" >> "$hits"
  done
  for r in "${regexes[@]}"; do
    xargs -0 grep -HInE -e "$r" < "$files" 2>/dev/null | sed "s#^#R\t$r\t#" >> "$hits"
  done
fi

# harmless lines: a comment, or a needle that sits only inside a sentence (a quoted string with a space: an error or log message) on a line that
# opens no file. A path-like string ("docs/x.md"), a bare word in a script, or any needle on a line with a file-access call is a hit.
filtered="$(mktemp)"; trap 'rm -f "$files" "$hits" "$filtered"' EXIT
awk -F'\t' '
  function sentences_removed(t,   out, i, c, q, lit, n) {  # drop every quoted string (" or `) that holds a space or tab: it is a message
    out = ""; n = length(t); i = 1
    while (i <= n) {
      c = substr(t, i, 1)
      if (c == "\"" || c == "`") {
        q = c; lit = c; i++
        while (i <= n) {
          c = substr(t, i, 1); lit = lit c; i++
          if (c == "\\" && q == "\"") { lit = lit substr(t, i, 1); i++; continue }
          if (c == q) break
        }
        if (lit ~ /[ \t]/) lit = ""
        out = out lit
      } else { out = out c; i++ }
    }
    return out
  }
  {
    kind = $1; needle = $2; rest = $3; for (k = 4; k <= NF; k++) rest = rest "\t" $k
    p = index(rest, ":"); file = substr(rest, 1, p - 1); r2 = substr(rest, p + 1)
    p = index(r2, ":"); lineno = substr(r2, 1, p - 1); text = substr(r2, p + 1)
    if (text ~ /^[ \t]*(\/\/|#|\*|\/\*|--)/ && text !~ /^[ \t]*\/\/go:/) next
    fa = "ReadFile|Open\\(|OpenFile|ReadDir|Stat\\(|Glob|Walk|embed|filepath\\.Join|path\\.Join|exec\\.Command|Mkdir|WriteFile|Create\\(|os\\.Args|Getenv|(^|[^A-Za-z])(cat|sed|grep|source|helm|kubectl|COPY|ADD|volumes|bufio) "
    if (text !~ fa) {
      t2 = sentences_removed(text); sub(/[ \t]+(\/\/|#) .*$/, "", t2)
      if (kind == "F" ? index(t2, needle) == 0 : t2 !~ needle) next
    }
    print file "\t" needle "\t" lineno "\t" text
  }' "$hits" | sort -u > "$filtered"
while IFS=$'\t' read -r file needle lineno text; do
  if [ -r "$exc" ] && awk -F'\t' -v f="$file" -v n="$needle" 'BEGIN{r=1} $0 !~ /^#/ && NF>=3 && $1==f && ($2==n || $2=="*") {r=0} END{exit r}' "$exc"; then continue; fi
  bad=1; echo "READER: $file:$lineno names '$needle' (on the allowlist): $text"
done < "$filtered"

# the one reader a text search cannot see: a make target. ci.yml must never call the chart check (it reads deploy/helm and ci/helm)
if grep -qE 'helm-check' .github/workflows/ci.yml; then bad=1; echo "READER: .github/workflows/ci.yml calls make helm-check (reads deploy/helm and ci/helm)"; fi

# an exception nobody needs any more is removed, so the list stays short and true
if [ -r "$exc" ]; then
  while IFS=$'\t' read -r f n _; do
    case "$f" in ''|'#'*) continue ;; esac
    if ! awk -F'\t' -v f="$f" -v n="$n" '$1==f && (n=="*" || $2==n) {r=1} END{exit !r}' "$filtered"; then
      bad=1; echo "STALE exception: $f $n matches no reader any more: delete the line"
    fi
  done < "$exc"
fi
if [ "$bad" = 1 ]; then
  echo "skip-guard: a file outside ci/skip-allowlist reads something the allowlist says no job reads. Remove that pattern from ci/skip-allowlist, or, when the line is harmless, add"
  echo "  <file><TAB><needle or *><TAB><reason>   to ci/skip-guard-exceptions (reviewed)."
  exit 1
fi
echo "skip-guard: ok (${#pats[@]} patterns, no unexplained reader)"
