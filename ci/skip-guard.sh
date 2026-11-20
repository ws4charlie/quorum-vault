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

# the files to read: tracked, not on the allowlist, not the machinery of this guard
files="$(mktemp)"; hits="$(mktemp)"; trap 'rm -f "$files" "$hits"' EXIT
git ls-files -z | while IFS= read -r -d '' f; do
  skip=0
  case "$f" in ci/changes.sh|ci/changes_test.sh|ci/classify.sh|ci/skip-allowlist|ci/skip-guard.sh|ci/skip-guard_test.sh|ci/skip-guard-exceptions) skip=1 ;; esac
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
bad=0
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
