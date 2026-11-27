#!/usr/bin/env bash
# The `build` job: compiles, once per CI run, everything the end-to-end jobs used to compile in each job.
#   1. the binaries the e2e harnesses start (e2e/mpcstack.GoBuild copies them from here when QV_E2E_PREBUILT names the directory; the names are
#      mpcstack.PrebuiltKey: the package directory with / as _, and @tags);
#   2. the test binary of every package that a make target in ci.yml runs with go test (the patterns come from `make -n`, exactly as the jobs run
#      them), and a manifest from each pattern to its packages, for ci/gotest.sh.
# Runs in the CI image (ci/run-in-image.sh ci/e2e-prebuild.sh <out dir>). A missing binary in a job is an error there (QV_E2E_PREBUILT_STRICT=1).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:?usage: ci/e2e-prebuild.sh <out dir>}"
rm -rf "$OUT"; mkdir -p "$OUT/bin" "$OUT/test"

# 1. <module dir> <package> <tags> : every build a harness asks for (e2e/btc, e2e/sol, e2e/custody harness_test.go; e2e/mpcstack Build, BuildTeeSim,
# BuildPartyAdmin; e2e/mpcsign and e2e/solsign stack_test.go; e2e/custody load_test.go)
BUILDS="
. ./cmd/qv-worker devauth
. ./cmd/qv-core -
. ./cmd/qv-gateway -
. ./cmd/qv-cold -
. ./cmd/qv-btc-xpub -
. ./cmd/qv-fee-caps -
. ./cmd/qv-approvers -
. ./cmd/qv-keysets -
. ./cmd/qv-rekey -
. ./cmd/qv-relay -
. ./cmd/qv-guardian -
. ./cmd/qv-approval-web -
. ./cmd/qv-sol-nonces -
. ./cmd/qv-cosigner -
. ./loadtest/cmd/qv-load -
mpc-party ./cmd/mpc-party -
mpc-party ./cmd/qv-party-admin -
mpc-party ./cmd/mpc-party teesim
mpc-party ./cmd/qv-attest-broker teesim
mpc-party ./internal/attest/cmd/qv-attest-ca teesim
"
while read -r mod pkg tags; do
  [ -n "$mod" ] || continue
  rel="${pkg#./}"; [ "$mod" = . ] || rel="$mod/$rel"
  key="${rel//\//_}"; args=()
  if [ "$tags" != - ]; then key="$key@${tags//,/+}"; args=(-tags "$tags"); fi
  echo "build $key"
  (cd "$mod" && go build ${args[@]+"${args[@]}"} -o "$OUT/bin/$key" "$pkg")
done <<< "$BUILDS"

# 2. test binaries: every package of every go test command of every make target ci.yml runs
: > "$OUT/test/manifest"
for t in $(grep -oE 'make +[A-Za-z0-9_.-]+' .github/workflows/ci.yml | awk '{print $2}' | sort -u); do
  cmds="$(make -n "$t" 2>/dev/null | grep -E '(^|[ ;&])(go test|ci/gotest\.sh) ')" || continue   # not a go test target (or a word in a comment)
  while IFS= read -r line; do
    for pat in $(printf '%s\n' "${line#*test }" | sed -E "s/'[^']*'//g" | tr ' ' '\n' | grep -E '^\./'); do
      grep -q "^$pat	" "$OUT/test/manifest" && continue
      dirs=""
      for d in $(go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.Dir}}{{end}}' "$pat"); do
        rel="${d#"$PWD"/}"; key="${rel//\//_}"
        if [ ! -e "$OUT/test/$key.test" ]; then echo "test binary $rel"; go test -c -o "$OUT/test/$key.test" "./$rel"; fi
        dirs="$dirs $rel"
      done
      printf '%s\t%s\n' "$pat" "${dirs# }" >> "$OUT/test/manifest"
    done
  done <<< "$cmds"
done
echo "prebuilt: $(ls "$OUT/bin" | wc -l) binaries, $(ls "$OUT/test" | grep -c '\.test$') test binaries"; cat "$OUT/test/manifest"
