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
# QV_CHECK_SET=release (the publish job): the -dev images are not built, so they are not checked
for d in $([ "${QV_CHECK_SET:-}" = release ] || echo "$QV_DEV_IMAGES"); do
  name="${d%%:*}"; img="${QV_IMAGE_PREFIX}${name}:${QV_IMAGE_TAG}"; b="${d##*:}"
  set +e
  out="$(docker run --rm --network none --read-only --cap-drop ALL --entrypoint "/usr/local/bin/$b" "$img" -h 2>&1)"; rc=$?
  lib="$(docker image inspect "$img" >/dev/null 2>&1 && docker create "$img" 2>/dev/null)"
  set -e
  have=no; if [ -n "$lib" ]; then docker cp "$lib:/usr/lib/softhsm/libsofthsm2.so" - >/dev/null 2>&1 && have=yes; docker rm -f "$lib" >/dev/null 2>&1; fi
  if [ "$rc" -le 2 ] && grep -qi usage <<<"$out" && [ "$have" = yes ]; then echo "ok   $name: $b -h, SoftHSM present"
  else echo "FAIL $name: $b -h exited $rc, SoftHSM library in the image: $have"; printf '%s\n' "$out" | head -8 | sed 's/^/    /'; fail=1; fi
done
# test-only code is absent from production binaries. These strings exist only in files behind `//go:build devauth` or `//go:build teesim`.
# probe <image> <binary> <string>: prints how many times the binary holds the string, or "no-image" / "no-binary" when the container cannot be made or the
# binary cannot be copied out or is empty. Both are failures: an empty input would otherwise count 0 and pass.
probe() {
  local cid bin n; cid="$(docker create "${QV_IMAGE_PREFIX}$1:${QV_IMAGE_TAG}" 2>/dev/null)" || { echo no-image; return; }
  bin="$(mktemp)"
  if docker cp "$cid:/usr/local/bin/$2" - 2>/dev/null | tar -xO > "$bin" 2>/dev/null && [ -s "$bin" ]; then n="$(grep -c -a -F -- "$3" "$bin" || true)"; else n=no-binary; fi
  rm -f "$bin"; docker rm -f "$cid" >/dev/null
  echo "$n"
}
# absent <image> <binary> <string> <what the string marks>: ok when the binary holds none of it; otherwise FAIL with the reason
absent() {
  local n; n="$(probe "$1" "$2" "$3")"
  case "$n" in
    0) echo "ok   $1 has no $4" ;;
    no-image) echo "FAIL $1: image ${QV_IMAGE_PREFIX}$1:${QV_IMAGE_TAG} missing (cannot check for $4)"; fail=1 ;;
    no-binary) echo "FAIL $1: binary not found (or empty) at /usr/local/bin/$2 (cannot check for $4)"; fail=1 ;;
    *) echo "FAIL $1 contains $4"; fail=1 ;;
  esac
}
absent mpc-party mpc-party 'sealer key file must hold 64 hex chars' 'insecure sealer'
absent mpc-party mpc-party 'I UNDERSTAND THIS PARTY SIGNS ANYTHING' 'dev-allow-all authorizer'
absent mpc-party mpc-party 'attest: mock attester has no CA' 'mock attester (teesim)'
absent qv-attest-broker qv-attest-broker 'attest: mock attester has no CA' 'mock attester (teesim)'
absent qv-worker qv-worker 'QV_FAILPOINT' 'failpoints'
# the approval page's files are in the image (the server is useless without them); output is captured, no `grep -q` on a pipe
cid="$(docker create "${QV_IMAGE_PREFIX}qv-approval-web:${QV_IMAGE_TAG}")"
for f in index.html app.js intent.js style.css; do
  set +e; docker cp "$cid:/srv/approval/$f" - >/dev/null 2>&1; rc=$?; set -e
  if [ "$rc" = 0 ]; then echo "ok   qv-approval-web has /srv/approval/$f"; else echo "FAIL qv-approval-web lacks /srv/approval/$f"; fail=1; fi
done
docker rm -f "$cid" >/dev/null
exit "$fail"
