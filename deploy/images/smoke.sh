#!/usr/bin/env bash
# Runs the binary of every image with -h under the settings a pod would have: no network, read-only root filesystem, no capabilities, no new privileges,
# the image's own (non-root) user. A binary that cannot start, that needs a library the base does not have, or that writes to its root filesystem fails.
# Also checks that a production image contains none of the test-only code: the binaries must not carry the strings only a -tags devauth build has.
#   deploy/images/smoke.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=images.sh
. deploy/images/images.sh
fail=0
RUN=(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges)
while IFS=: read -r name zone bins; do
  img="${QV_IMAGE_PREFIX}${name}:${QV_IMAGE_TAG}"
  for b in ${bins//,/ }; do
    set +e
    # -h makes Go's flag package print the usage (exit 0 or 2); the subcommand tools (qv-route, qv-fee-caps, qv-approvers, qv-guardian) print theirs
    # and exit 1 for -h, so a second try without arguments counts too. What fails: a binary that does not start, a missing library, a write to the root fs.
    out="$("${RUN[@]}" --entrypoint "/usr/local/bin/$b" "$img" -h 2>&1)"; rc=$?
    if ! { [ "$rc" -le 2 ] && grep -qi 'usage' <<<"$out"; }; then out="$("${RUN[@]}" --entrypoint "/usr/local/bin/$b" "$img" 2>&1)"; rc=$?; fi
    set -e
    if [ "$rc" -le 2 ] && grep -qi 'usage' <<<"$out"; then
      echo "ok   $name: $b prints its usage"
    else
      echo "FAIL $name: $b exited $rc"; printf '%s\n' "$out" | head -5 | sed 's/^/    /'; fail=1
    fi
  done
done < <(qv_all_images | grep -v -- '-dev:' )
# the -dev images: same binaries, and SoftHSM present. Output is captured first, never piped into `grep -q` (it exits early, the writer gets SIGPIPE and
# `pipefail` turns a pass into a random failure), and a failure prints what the command said.
for d in $QV_DEV_IMAGES; do
  name="${d%%:*}"; img="${QV_IMAGE_PREFIX}${name}:${QV_IMAGE_TAG}"; b="${d##*:}"
  set +e
  out="$(docker run --rm --network none --read-only --cap-drop ALL --entrypoint "/usr/local/bin/$b" "$img" -h 2>&1)"; rc=$?
  lib="$(docker image inspect "$img" >/dev/null 2>&1 && docker create "$img" 2>/dev/null)"
  set -e
  have=no; if [ -n "$lib" ]; then docker cp "$lib:/usr/lib/softhsm/libsofthsm2.so" - >/dev/null 2>&1 && have=yes; docker rm -f "$lib" >/dev/null 2>&1; fi
  if [ "$rc" -le 2 ] && grep -qi usage <<<"$out" && [ "$have" = yes ]; then echo "ok   $name: $b -h, SoftHSM present"
  else echo "FAIL $name: $b -h exited $rc, SoftHSM library in the image: $have"; printf '%s\n' "$out" | head -8 | sed 's/^/    /'; fail=1; fi
done
# test-only code is absent from production binaries. These strings exist only in files behind `//go:build devauth`.
probe() { # probe <image> <binary> <string>
  local cid; cid="$(docker create "${QV_IMAGE_PREFIX}$1:${QV_IMAGE_TAG}")"; docker cp "$cid:/usr/local/bin/$2" - 2>/dev/null | tar -xO 2>/dev/null | grep -c -a -F -- "$3" || true; docker rm -f "$cid" >/dev/null
}
n="$(probe mpc-party mpc-party 'sealer key file must hold 64 hex chars')"; [ "$n" = 0 ] && echo "ok   mpc-party has no insecure sealer" || { echo "FAIL mpc-party contains the insecure sealer"; fail=1; }
n="$(probe mpc-party mpc-party 'I UNDERSTAND THIS PARTY SIGNS ANYTHING')"; [ "$n" = 0 ] && echo "ok   mpc-party has no dev-allow-all authorizer" || { echo "FAIL mpc-party contains dev-allow-all"; fail=1; }
n="$(probe qv-attest-broker qv-attest-broker 'attest: mock attester has no CA')"; [ "$n" = 0 ] && echo "ok   qv-attest-broker has no mock attester (no teesim)" || { echo "FAIL qv-attest-broker contains the teesim mock attester"; fail=1; }
n="$(probe qv-worker qv-worker 'QV_FAILPOINT')"; [ "$n" = 0 ] && echo "ok   qv-worker has no failpoints" || { echo "FAIL qv-worker contains failpoints"; fail=1; }
# the approval page's files are in the image (the server is useless without them); output is captured, no `grep -q` on a pipe
cid="$(docker create "${QV_IMAGE_PREFIX}qv-approval-web:${QV_IMAGE_TAG}")"
for f in index.html app.js intent.js style.css; do
  set +e; docker cp "$cid:/srv/approval/$f" - >/dev/null 2>&1; rc=$?; set -e
  if [ "$rc" = 0 ]; then echo "ok   qv-approval-web has /srv/approval/$f"; else echo "FAIL qv-approval-web lacks /srv/approval/$f"; fail=1; fi
done
docker rm -f "$cid" >/dev/null
exit "$fail"
