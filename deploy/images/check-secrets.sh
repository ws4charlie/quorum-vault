#!/usr/bin/env bash
# Fails when a layer of an image holds a file that looks like a secret, or when a zone holds the other zone's binary, or when the image does not run as
# a non-root user. The repository is public: no key, PIN, certificate or .env value may ever be in an image.
#
#   deploy/images/check-secrets.sh [image ...]     default: every image of images.sh, as ${QV_IMAGE_PREFIX}<name>:${QV_IMAGE_TAG}
#
# It reads the file names of every layer (docker save), not only the final filesystem: a file added in one layer and deleted in the next is still
# in the image. The patterns are deliberately wide; a false positive is fixed by not shipping that file, never by editing the list.
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=images.sh
. deploy/images/images.sh
# secret-looking paths (extended regex on the path inside the layer)
SECRET_RE='(^|/)(\.env(\..*)?|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|\.netrc|\.npmrc|\.pgpass|\.git-credentials|credentials|\.aws|\.ssh|\.gnupg|\.docker/config\.json|kubeconfig|\.kube/config|[^/]*\.(pem|key|crt|cer|der|p12|pfx|jks|keystore|sealed|token|pin|secret|secrets|kdbx)|tls\.(key|crt)|ca\.(key|crt)|[^/]*\.(key|pin)\.[a-z]+|pin(_file)?|secrets?(\.[a-z]+)?|(var/lib/)?softhsm/tokens(/.*)?|data/(pki|softhsm)(/.*)?)$'
# the one exception: the system CA bundle of the base image is public trust data, not a secret
ALLOW_RE='^(etc/ssl/certs/|usr/share/ca-certificates/|etc/ca-certificates|usr/lib/ssl/)'
fail=0
if [ $# -gt 0 ]; then images=("$@"); else images=(); while IFS=: read -r n _ _; do images+=("${QV_IMAGE_PREFIX}${n}:${QV_IMAGE_TAG}"); done < <(qv_all_images); fi
for img in "${images[@]}"; do
  name="${img##*/}"; name="${name%%:*}"
  zone="$(qv_all_images | awk -F: -v n="$name" '$1==n{print $2}')"
  tmp="$(mktemp -d)"
  docker save "$img" -o "$tmp/i.tar"
  mkdir "$tmp/x"; tar -xf "$tmp/i.tar" -C "$tmp/x"
  # every layer's file list (OCI layout: blobs referenced from the manifest; docker save also writes a manifest.json)
  files="$tmp/files"; : >"$files"
  for l in $(python3 - "$tmp/x" <<'PY'
import json, os, sys
root = sys.argv[1]
def blob(d):
    return os.path.join(root, "blobs", d.replace("sha256:", "sha256/"))
seen = set()
def walk(path):
    with open(path) as f:
        m = json.load(f)
    for d in m.get("manifests", []):
        p = blob(d["digest"])
        walk(p)
    for l in m.get("layers", []):
        seen.add(blob(l["digest"]))
idx = os.path.join(root, "index.json")
walk(idx)
print("\n".join(sorted(seen)))
PY
  ); do tar -tf "$l" 2>/dev/null | sed 's#^\./##' >>"$files" || true; done
  [ -s "$files" ] || { echo "FATAL: $img: no layer files listed (image format?)"; exit 1; }
  bad="$(grep -E "$SECRET_RE" "$files" | grep -Ev "$ALLOW_RE" | grep -Ev '/$' || true)"
  if [ -n "$bad" ]; then echo "FAIL $img: secret-looking files in a layer:"; echo "$bad" | sed 's/^/    /'; fail=1; fi
  # zones: no binary of the other zone
  other="$QV_SIGNING_BINS"; [ "$zone" = signing ] && other="$QV_BUSINESS_BINS"
  if [ -n "$zone" ]; then for b in $other; do
    case " $QV_ZONE_ALLOW " in *" $name:$b "*) continue ;; esac   # the documented exception (images.sh)
    if grep -qE "(^|/)$b\$" "$files"; then echo "FAIL $img ($zone zone) contains the other zone's binary $b"; fail=1; fi
  done; fi
  # non-root
  user="$(docker image inspect -f '{{.Config.User}}' "$img")"
  case "$user" in ""|0|root|0:*|root:*) echo "FAIL $img runs as root (Config.User='$user')"; fail=1 ;; esac
  rm -rf "$tmp"
  [ "$fail" = 0 ] && echo "ok   $img (user $user)"
done
exit "$fail"
