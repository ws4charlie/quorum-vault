#!/usr/bin/env bash
# Checks a release manifest against the registry, from the outside (anyone can run it; the images are public, no login needed). For every image of the manifest:
#   1. the signature verifies with cosign, and the signer is exactly the workflow identity and issuer the manifest names (keyless, GitHub OIDC);
#   2. the version tag in the registry still points at the manifest's digest (a moved or deleted tag is reported);
#   3. an SBOM and a provenance attestation are attached to the image index.
# And the manifest's own signature bundle (release-<version>.json.sigstore.json, beside it) verifies, when the file exists.
#
#   deploy/images/verify-release.sh release-v1.2.3.json
#
# Needs cosign (v2 or later), docker with buildx, python3. The identity it expects is read from the manifest, then compared with the one the repository's
# workflow can have: a manifest cannot talk this script into trusting another signer.
set -euo pipefail
m="${1:?usage: verify-release.sh release-<version>.json}"
[ -f "$m" ] || { echo "no such file: $m" >&2; exit 2; }
ISSUER="https://token.actions.githubusercontent.com"
read -r version repo identity issuer dry < <(python3 -I - "$m" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print(m["version"], m["source"]["repository"].replace("https://github.com/", ""), m["signer"]["identity"] or "-", m["signer"]["issuer"] or "-", str(m["dryRun"]).lower())
PY
)
[ "$dry" = false ] || { echo "FAIL $m comes from a dry run: nothing was published" >&2; exit 1; }
want="https://github.com/$repo/.github/workflows/images.yml@refs/tags/$version"
[ "$identity" = "$want" ] || { echo "FAIL manifest signer identity '$identity' is not '$want'" >&2; exit 1; }
[ "$issuer" = "$ISSUER" ] || { echo "FAIL manifest issuer '$issuer' is not '$ISSUER'" >&2; exit 1; }
fail=0
while read -r name digest repository; do
  ref="$repository@$digest"
  if cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" "$ref" >/dev/null 2>&1; then echo "ok   $name: signature ($identity)"
  else echo "FAIL $name: cosign verify failed for $ref"; fail=1; fi
  tagdigest="$(docker buildx imagetools inspect "$repository:$version" --format '{{.Manifest.Digest}}' 2>/dev/null || true)"
  if [ "$tagdigest" = "$digest" ]; then echo "ok   $name: $version -> $digest"; else echo "FAIL $name: tag $version points at '${tagdigest:-nothing}', manifest says $digest"; fail=1; fi
  for kind in SBOM Provenance; do
    out="$(docker buildx imagetools inspect "$ref" --format "{{json .$kind}}" 2>/dev/null || true)"
    case "$out" in ""|null|"{}") echo "FAIL $name: no $kind attached"; fail=1 ;; *) echo "ok   $name: $kind attached" ;; esac
  done
done < <(python3 -I -c 'import json,sys; [print(n, i["digest"], i["repository"]) for n, i in sorted(json.load(open(sys.argv[1]))["images"].items())]' "$m")
if [ -f "$m.sigstore.json" ]; then
  if cosign verify-blob --bundle "$m.sigstore.json" --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" "$m" >/dev/null 2>&1; then echo "ok   manifest signature"
  else echo "FAIL manifest signature does not verify"; fail=1; fi
else echo "note no $m.sigstore.json beside the manifest: its own signature was not checked"; fi
exit "$fail"
