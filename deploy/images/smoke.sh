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
    # -h makes Go's flag package print the usage; its exit status is 0 (flag.ExitOnError) or 2 (ContinueOnError); mpc-party prints a usage too.
    out="$("${RUN[@]}" --entrypoint "/usr/local/bin/$b" "$img" -h 2>&1)"; rc=$?
    set -e
    if { [ "$rc" = 0 ] || [ "$rc" = 2 ]; } && printf '%s' "$out" | grep -qi 'usage'; then
      echo "ok   $name: $b -h"
    else
      echo "FAIL $name: $b -h exited $rc"; printf '%s\n' "$out" | head -5 | sed 's/^/    /'; fail=1
    fi
  done
done < <(qv_all_images | grep -v -- '-dev:' )
# the -dev images: same binaries, and SoftHSM present
for d in $QV_DEV_IMAGES; do
  name="${d%%:*}"; img="${QV_IMAGE_PREFIX}${name}:${QV_IMAGE_TAG}"; b="${d##*:}"
  if docker run --rm --network none --read-only --cap-drop ALL --entrypoint "/usr/local/bin/$b" "$img" -h 2>&1 | grep -qi usage \
     && docker run --rm --network none --read-only --entrypoint /usr/bin/test "$img" -f /usr/lib/softhsm/libsofthsm2.so; then echo "ok   $name: $b -h, SoftHSM present"
  else echo "FAIL $name"; fail=1; fi
done
# test-only code is absent from production binaries. These strings exist only in files behind `//go:build devauth`.
probe() { # probe <image> <binary> <string>
  local cid; cid="$(docker create "${QV_IMAGE_PREFIX}$1:${QV_IMAGE_TAG}")"; docker cp "$cid:/usr/local/bin/$2" - 2>/dev/null | tar -xO 2>/dev/null | grep -c -a -F -- "$3" || true; docker rm -f "$cid" >/dev/null
}
n="$(probe mpc-party mpc-party 'insecure-static-key-for-tests')"; [ "$n" = 0 ] && echo "ok   mpc-party has no insecure sealer" || { echo "FAIL mpc-party contains the insecure sealer"; fail=1; }
n="$(probe mpc-party mpc-party 'I UNDERSTAND THIS PARTY SIGNS ANYTHING')"; [ "$n" = 0 ] && echo "ok   mpc-party has no dev-allow-all authorizer" || { echo "FAIL mpc-party contains dev-allow-all"; fail=1; }
n="$(probe qv-worker qv-worker 'QV_FAILPOINT')"; [ "$n" = 0 ] && echo "ok   qv-worker has no failpoints" || { echo "FAIL qv-worker contains failpoints"; fail=1; }
exit "$fail"
