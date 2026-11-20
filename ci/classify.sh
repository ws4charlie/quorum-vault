#!/usr/bin/env bash
# Decides, from the changed files of a pull request, whether the heavy jobs of .github/workflows/ci.yml may be skipped.
#   git diff --raw -z --no-renames --no-abbrev <base> <merge commit> | ci/classify.sh
# Prints exactly one line:  skip <class> <number of files>   or   all <reason>.   Nothing but a line of the first form allows a skip.
# The rule: skip only when EVERY changed file is added, modified or deleted as a plain file (mode 100644) and matches a line of ci/skip-allowlist.
# Anything else, and every doubt (no files, too many files, a mode change, a symlink, a submodule, a rename seen as a path outside the list, a
# path that is not plain, an unreadable allowlist, a stream that does not parse), is `all`: run everything.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
MAX_FILES=1000

all() { echo "all $*"; exit 0; }

allow="$here/skip-allowlist"
[ -r "$allow" ] || all "no allowlist"
classes=(); pats=()
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ''|'#'*) continue ;; esac
  read -r c p extra <<<"$line"
  [ -z "${extra:-}" ] || all "bad allowlist line"
  case "$c" in docs|chart) ;; *) all "bad allowlist class" ;; esac
  case "$p" in ''|'*'*|/*|*..*) all "bad allowlist pattern" ;; esac
  classes+=("$c"); pats+=("$p")
done < "$allow"
[ "${#pats[@]}" -gt 0 ] || all "empty allowlist"

# trees that may be skipped although their files have a risky extension (ci/skip-module-exceptions, checked by ci/skip-guard.sh)
trees=()
if [ -r "$here/skip-module-exceptions" ]; then
  while IFS=$'\t' read -r t _ || [ -n "$t" ]; do
    case "$t" in ''|'#'*) continue ;; */) trees+=("$t") ;; *) all "bad module exception" ;; esac
  done < "$here/skip-module-exceptions"
fi

n=0; docs=0; chart=0
while IFS= read -r -d '' meta; do
  IFS= read -r -d '' path || all "truncated change list"
  n=$((n + 1))
  [ "$n" -le "$MAX_FILES" ] || all "more than $MAX_FILES files"
  case "$meta" in :*) ;; *) all "unparsable change list" ;; esac
  read -r om nm _ _ st rest <<<"${meta#:}"
  [ -z "${rest:-}" ] || all "unparsable change list"
  case "$st:$om:$nm" in
    A:000000:100644|M:100644:100644|D:100644:000000) ;;
    *) all "not a plain add, modify or delete of a regular file ($st $om $nm)" ;;
  esac
  [ -n "$path" ] || all "empty path"
  case "$path" in /*|*//*) all "odd path" ;; esac
  case "/$path/" in */../*|*/./*) all "odd path" ;; esac
  if [[ "$path" =~ [[:cntrl:]\\] ]]; then all "odd path"; fi
  hit=""
  for i in "${!pats[@]}"; do
    # shellcheck disable=SC2254
    case "$path" in ${pats[$i]}) hit="${classes[$i]}"; break ;; esac
  done
  [ -n "$hit" ] || all "not on the allowlist: $path"
  # belt and braces: a file a job compiles or runs is never skipped, whatever the list says, unless its tree is a reviewed own-module exception
  case "${path##*/}" in
    *.go|go.mod|go.sum|*.sh|*.bash|*.py|*.sql|*.proto|*.mk|*.js|Makefile|Dockerfile*|*.Dockerfile)
      ok=0; for t in "${trees[@]+"${trees[@]}"}"; do case "$path" in "$t"*) ok=1 ;; esac; done
      [ "$ok" = 1 ] || all "a file that a job compiles or runs is never skipped: $path" ;;
  esac
  case "$hit" in docs) docs=1 ;; chart) chart=1 ;; esac
done
[ -z "${meta:-}" ] || all "truncated change list"
[ "$n" -gt 0 ] || all "no changed files"

if [ "$docs" = 1 ] && [ "$chart" = 1 ]; then echo "skip docs+chart $n"
elif [ "$docs" = 1 ]; then echo "skip docs $n"
else echo "skip chart $n"; fi
