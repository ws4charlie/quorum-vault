#!/usr/bin/env bash
# Checks a release manifest against the registry, from the outside (anyone can run it; the images are public, no login needed). FAIL CLOSED: nothing in the
# manifest is used before its own signature has verified.
#   0. the manifest's signature bundle (default: <manifest>.sigstore.json) must exist and verify with cosign against the identity of THIS repository's release
#      workflow for the manifest's version. No bundle, no verification.
#   1. then, for every image: the repository is exactly ghcr.io/ws4charlie/quorum-vault/<name>; the image signature verifies with the same identity;
#      the image's own label org.opencontainers.image.title is <name> (so a manifest that swaps two entries is caught: the digest must be that name's image);
#      the version tag still points at the digest; an SBOM and a provenance attestation are attached.
#
#   deploy/images/verify-release.sh release-v1.2.3.json [bundle]
#
# The repository, registry path and signer are CONSTANTS here, never read from the manifest: a manifest naming another repository cannot make this script
# trust that repository's signatures. Needs cosign (v2 or later), docker with buildx, python3.
set -euo pipefail
REPO="ws4charlie/quorum-vault"
REGISTRY="ghcr.io/$REPO"
ISSUER="https://token.actions.githubusercontent.com"
VERSION_RE='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$'
m="${1:?usage: verify-release.sh release-<version>.json [bundle]}"
bundle="${2:-$m.sigstore.json}"
# absolute paths first: the script then runs from the repository root (images.sh)
abs() { [ -e "$1" ] && echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")" || echo "$1"; }
m="$(abs "$m")"; bundle="$(abs "$bundle")"
cd "$(dirname "$0")/../.."
die() { echo "FAIL $*" >&2; exit 1; }
[ -f "$m" ] || die "no such file: $m"
[ -f "$bundle" ] || die "no signature bundle $bundle: an unsigned manifest is not verified (fail closed)"
# The version is read first only to name the identity the signature must have; it is checked against the format, and the signature is checked before anything else is used.
version="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version",""))' "$m")" || die "$m is not JSON"
[[ "$version" =~ $VERSION_RE ]] || die "manifest version '$version' is not vMAJOR.MINOR.PATCH[-rc.N]"
identity="https://github.com/$REPO/.github/workflows/images.yml@refs/tags/$version"
cosign verify-blob --bundle "$bundle" --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" "$m" >/dev/null 2>&1 \
  || die "manifest signature does not verify against $identity"
echo "ok   manifest signature ($identity)"

# From here on the manifest is authentic: it was written by this repository's release workflow for this tag. Still checked against the constants.
# shellcheck source=images.sh
. deploy/images/images.sh
want="$(qv_release_images | cut -d: -f1 | sort | tr '\n' ' ')"
python3 -I - "$m" "$REPO" "$REGISTRY" "$version" "$want" <<'PY' || exit 1
import json, re, sys
m, repo, registry, version, want = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5].split()
def bad(msg): print("FAIL " + msg, file=sys.stderr); sys.exit(1)
if m.get("schema") != 1: bad("unknown manifest schema")
if m.get("dryRun") is not False: bad("manifest comes from a dry run: nothing was published")
if m["source"]["repository"] != "https://github.com/" + repo: bad("manifest names repository %r, not %s" % (m["source"]["repository"], repo))
if m["signer"]["identity"] != "https://github.com/%s/.github/workflows/images.yml@refs/tags/%s" % (repo, version): bad("manifest signer identity is not this repository's workflow for %s" % version)
if m["signer"]["issuer"] != "https://token.actions.githubusercontent.com": bad("manifest issuer is not GitHub's")
if sorted(m["images"]) != sorted(want): bad("manifest images %s differ from the release set %s" % (sorted(m["images"]), sorted(want)))
for n, i in m["images"].items():
    if i["repository"] != registry + "/" + n: bad("image %s: repository %r, want %s/%s" % (n, i["repository"], registry, n))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", i["digest"]) or set(i["digest"][7:]) == {"0"}: bad("image %s: bad digest" % n)
PY
fail=0
while read -r name digest; do
  repository="$REGISTRY/$name"; ref="$repository@$digest"
  if cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" "$ref" >/dev/null 2>&1; then echo "ok   $name: signature ($identity)"
  else echo "FAIL $name: cosign verify failed for $ref"; fail=1; fi
  # The entry must name the right binary's image: the digest's own title label is the name (the label is inside the signed image).
  cfg="$(docker buildx imagetools inspect "$ref" --format '{{json .Image}}' 2>/dev/null || true)"
  title="$(python3 -I -c '
import json, sys
try: o = json.loads(sys.argv[1])
except Exception: sys.exit(0)
if not isinstance(o, dict): sys.exit(0)
cfgs = [o] if "config" in o else list(o.values())
t = {((c.get("config") or {}).get("Labels") or {}).get("org.opencontainers.image.title") for c in cfgs if isinstance(c, dict)}
t.discard(None)
print(",".join(sorted(t)))' "$cfg")"
  if [ "$title" = "$name" ]; then echo "ok   $name: the image at that digest is $name"; else echo "FAIL $name: the image at $digest says it is '${title:-nothing}' (swapped or wrong entry)"; fail=1; fi
  tagdigest="$(docker buildx imagetools inspect "$repository:$version" --format '{{.Manifest.Digest}}' 2>/dev/null || true)"
  if [ "$tagdigest" = "$digest" ]; then echo "ok   $name: $version -> $digest"; else echo "FAIL $name: tag $version points at '${tagdigest:-nothing}', manifest says $digest"; fail=1; fi
  for kind in SBOM Provenance; do
    out="$(docker buildx imagetools inspect "$ref" --format "{{json .$kind}}" 2>/dev/null || true)"
    case "$out" in ""|null|"{}") echo "FAIL $name: no $kind attached"; fail=1 ;; *) echo "ok   $name: $kind attached" ;; esac
  done
done < <(python3 -I -c 'import json,sys; [print(n, i["digest"]) for n, i in sorted(json.load(open(sys.argv[1]))["images"].items())]' "$m")
exit "$fail"
