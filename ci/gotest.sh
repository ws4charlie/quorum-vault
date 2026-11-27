#!/usr/bin/env bash
# `go test` for the end-to-end groups in CI (Makefile: QV_GOTEST=ci/gotest.sh): runs the test binaries the `build` job compiled (ci/e2e-prebuild.sh),
# in each package's directory as go test does, with the same flags. Anything it does not fully understand (a flag, a package pattern the manifest does
# not list, no QV_E2E_TESTBIN) runs the real `go test` with the same arguments, so it can only save time, never change what runs.
#   QV_E2E_TESTBIN=<dir with manifest and *.test> ci/gotest.sh -count=1 -p 1 -timeout 25m -v -run 'X' -skip 'Y' ./e2e/btc/...
set -uo pipefail
real() { echo "gotest: $1; running go test" >&2; exec go test "${orig[@]}"; }
orig=("$@")
dir="${QV_E2E_TESTBIN:-}"
[ -n "$dir" ] && [ -r "$dir/manifest" ] || real "no prebuilt test binaries"
root="$(cd "$(dirname "$0")/.." && pwd)"

flags=(); pats=(); timeout=""
while [ $# -gt 0 ]; do
  case "$1" in
    -count=*) flags+=("-test.count=${1#-count=}") ;;
    -p) shift ;;                                   # one package at a time anyway
    -p=*) ;;
    -v) flags+=(-test.v) ;;
    -timeout) timeout="$2"; shift ;;
    -timeout=*) timeout="${1#-timeout=}" ;;
    -run) flags+=("-test.run=$2"); shift ;;
    -run=*) flags+=("-test.run=${1#-run=}") ;;
    -skip) flags+=("-test.skip=$2"); shift ;;
    -skip=*) flags+=("-test.skip=${1#-skip=}") ;;
    ./*) pats+=("$1") ;;
    *) real "flag $1 is not modelled" ;;
  esac
  shift
done
[ "${#pats[@]}" -gt 0 ] || real "no package"
flags+=("-test.timeout=${timeout:-10m}" -test.paniconexit0)   # what go test passes by default

dirs=()
for p in "${pats[@]}"; do
  line="$(awk -F'\t' -v p="$p" '$1 == p {print $2; n++} END {exit n != 1}' "$dir/manifest")" || real "package pattern $p is not in the manifest"
  for d in $line; do
    [ -x "$dir/${d//\//_}.test" ] || real "no test binary for $d"
    dirs+=("$d")
  done
done
rc=0
for d in ${dirs[@]+"${dirs[@]}"}; do
  start=$(date +%s)
  (cd "$root/$d" && "$dir/${d//\//_}.test" "${flags[@]}"); r=$?
  if [ "$r" = 0 ]; then echo "ok  	$d	$(( $(date +%s) - start ))s (prebuilt)"; else echo "FAIL	$d	$(( $(date +%s) - start ))s (prebuilt)"; rc=1; fi
done
exit "$rc"
