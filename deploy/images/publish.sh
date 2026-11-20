#!/usr/bin/env bash
# Builds every RELEASE image (production images only: never a -dev or tee-sim variant), and, only when PUBLISH=1, pushes it to the registry, attaches an
# SBOM and build provenance, and signs the pushed digest with cosign (keyless: the GitHub OIDC identity of the workflow run). Always writes the release
# manifest OUT/release-<version>.json (name, digest, source commit, signer identity per image).
#
# ONLY the `publish` job of .github/workflows/images.yml runs this. Nobody runs it from a laptop. DRY RUN is the default: without PUBLISH=1 nothing is pushed,
# nothing is signed, and no registry login is needed; the images are built to OCI archives under OUT and the manifest says "dryRun": true. The pull-request
# run of the workflow does exactly this, so the build, the digest extraction and the manifest are exercised before the first real release.
#
# Environment:
#   VERSION     the release version, e.g. v1.2.3 or v1.2.3-rc.1 (the dry run uses v0.0.0-dryrun.<sha7>); checked here against the same rule as release-gate.sh
#   COMMIT      the source commit (default: git HEAD)
#   REGISTRY    default ghcr.io/<owner>/<repo>, lower-case, from GITHUB_REPOSITORY; each image is $REGISTRY/<name>
#   PUBLISH     1 = push and sign (needs `docker login` and an OIDC token: id-token: write); anything else = dry run
#   ONLY        dry run only (refused with PUBLISH=1): build just these images, space-separated, to try the script locally without cb-mpc
#   OUT         output directory (default: a new temporary directory; the path is printed). A real release also writes pushed.tsv (each digest as soon as
#               it is pushed, before its signature) and signed.tsv (after it): the workflow uploads them even when the job fails, as the record of a
#               half-published release (runbook: "A release failed half way")
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=images.sh
. deploy/images/images.sh

# tag_state <ref>: the registry's own answer for a tag. Prints and returns: absent (0: the registry said "not found"), exists:<digest> (10), error (11: ANY
# other failure: network, auth, rate limit, a 5xx). Only an explicit "not found" counts as absent; everything else stops the release, because pushing after
# a failed lookup could overwrite a published version.
tag_state() {
  local out rc=0
  out="$(docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}' 2>&1)" || rc=$?
  if [ "$rc" = 0 ] && [[ "$out" =~ ^sha256:[0-9a-f]{64}$ ]]; then echo "exists:$out"; return 10; fi
  # "not found" only as buildx prints it for a 404 (a single line ending in ": not found"), or the registry's own error codes. A message that merely
  # mentions it among others (a proxy page, a timeout) is an error.
  if [ "$rc" != 0 ] && { [ "$(wc -l <<<"$out")" -le 1 ] && grep -qE '^ERROR: .*: not found$' <<<"$out" || grep -qE 'MANIFEST_UNKNOWN|NAME_UNKNOWN' <<<"$out"; }; then echo absent; return 0; fi
  echo "error: ${out:-no output}" | head -3; return 11
}
if [ "${1:-}" = --tag-state ]; then tag_state "${2:?ref}"; exit $?; fi   # for the tests
: "${VERSION:?VERSION, e.g. v1.2.3}"
: "${COMMIT:=$(git rev-parse HEAD)}"
: "${GITHUB_REPOSITORY:=ws4charlie/quorum-vault}"
repo_lc="$(printf '%s' "$GITHUB_REPOSITORY" | tr 'A-Z' 'a-z')"
: "${REGISTRY:=ghcr.io/$repo_lc}"
: "${PUBLISH:=0}"
: "${OUT:=$(mktemp -d)}"; mkdir -p "$OUT"
: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct "$COMMIT")}"; export SOURCE_DATE_EPOCH
ISSUER="https://token.actions.githubusercontent.com"
SOURCE_URL="https://github.com/$GITHUB_REPOSITORY"

# A real release needs a release version; the dry run may use the dry-run pseudo version.
if [ "$PUBLISH" = 1 ]; then
  deploy/images/release-gate.sh --check-version "$VERSION" || { echo "publish.sh: '$VERSION' is not vMAJOR.MINOR.PATCH[-rc.N]" >&2; exit 1; }
  # the workflow identity a verifier must expect (job_workflow_ref of the keyless certificate)
  IDENTITY="$SOURCE_URL/.github/workflows/images.yml@refs/tags/$VERSION"
else
  IDENTITY=""
fi

images="$(qv_release_images | cut -d: -f1 | tr '\n' ' ')"
if [ -n "${ONLY:-}" ]; then
  [ "$PUBLISH" = 1 ] && { echo "publish.sh: ONLY is for dry runs; a release publishes every image" >&2; exit 1; }
  for n in $ONLY; do case " $images " in *" $n "*) ;; *) echo "publish.sh: ONLY: '$n' is not a release image" >&2; exit 1 ;; esac; done
  images="$ONLY"
fi
# Defence in depth: a development or simulated image never gets a release name, whatever images.sh says.
for n in $images; do case "$n" in *-dev|*-dev-*|*teesim*|*tee-sim*|*softhsm*) echo "publish.sh: refusing to publish '$n': development or simulated images are never released" >&2; exit 1 ;; esac; done

digest_of_oci() { # digest_of_oci <archive.tar>: the digest of the top-level manifest (index) of an OCI layout, which is the digest a push would give
  python3 -I - "$1" <<'PY'
import hashlib, sys, tarfile
t = tarfile.open(sys.argv[1])
idx = t.extractfile("index.json").read()
import json
m = json.loads(idx)["manifests"]
assert len(m) == 1, "expected one top-level manifest, got %d" % len(m)
print(m[0]["digest"])
PY
}

: >"$OUT/digests.tsv"
for name in $images; do
  echo "== $name" >&2
  ref="$REGISTRY/$name:$VERSION"
  # A published version is immutable: never push over an existing tag. Only the registry's explicit "not found" lets the push go on; an existing tag
  # (same digest or not: this run has not built it yet, and a half-published release is cleaned up, not resumed) and any other answer stop the release.
  if [ "$PUBLISH" = 1 ]; then
    rc=0; st="$(tag_state "$ref")" || rc=$?
    case "$rc" in
      0) ;;
      10) echo "publish.sh: $ref already exists (${st#exists:}): versions are never overwritten; publish a new patch version, or clean up a half-published release (docs/runbooks/release.md)" >&2; exit 1 ;;
      *) echo "publish.sh: cannot tell whether $ref exists, not pushing: $st" >&2; exit 1 ;;
    esac
  fi
  common=(--file deploy/images/Dockerfile --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" --target "$name" --sbom=true --provenance=mode=max
          --label "org.opencontainers.image.title=$name" --label "org.opencontainers.image.source=$SOURCE_URL" --label "org.opencontainers.image.revision=$COMMIT" --label "org.opencontainers.image.version=$VERSION"
          --metadata-file "$OUT/$name.metadata.json")
  # The source label links the package to this repository on GitHub (so the workflow's token may write it, and the package page shows the source). The same
  # annotation on the index and the manifests makes it visible to the registry, whose "container image" is the index once an SBOM is attached.
  ann="annotation-index.org.opencontainers.image.source=$SOURCE_URL,annotation-manifest.org.opencontainers.image.source=$SOURCE_URL"
  if [ "$PUBLISH" = 1 ]; then
    docker buildx build "${common[@]}" --output "type=image,name=$ref,push=true,rewrite-timestamp=true,$ann" .
    digest="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$OUT/$name.metadata.json")"
    # Record the pushed digest BEFORE signing, so a failure later in this script (or in a later job step) never leaves pushed images unrecorded.
    printf '%s\t%s\n' "$name" "$digest" >>"$OUT/pushed.tsv"
    cosign sign --yes "$REGISTRY/$name@$digest"
    printf '%s\t%s\n' "$name" "$digest" >>"$OUT/signed.tsv"
  else
    docker buildx build "${common[@]}" --output "type=oci,dest=$OUT/$name.oci.tar,rewrite-timestamp=true,$ann" .
    digest="$(digest_of_oci "$OUT/$name.oci.tar")"
  fi
  case "$digest" in sha256:[0-9a-f]*) [ "${#digest}" = 71 ] || { echo "publish.sh: bad digest '$digest' for $name" >&2; exit 1; } ;; *) echo "publish.sh: bad digest '$digest' for $name" >&2; exit 1 ;; esac
  printf '%s\t%s\n' "$name" "$digest" >>"$OUT/digests.tsv"
  echo "$REGISTRY/$name@$digest$([ "$PUBLISH" = 1 ] || echo '  (dry run: not pushed)')" >&2
done

MANIFEST="$OUT/release-$VERSION.json"
python3 -I - "$MANIFEST" "$OUT/digests.tsv" <<PY
import json, sys
out, tsv = sys.argv[1], sys.argv[2]
zones = {}
for line in """$(qv_release_images)""".split():
    n, z, b = line.split(":")
    zones[n] = {"zone": z, "binaries": b.split(",")}
images = {}
for line in open(tsv):
    n, d = line.rstrip("\n").split("\t")
    images[n] = {"repository": "$REGISTRY/" + n, "digest": d, "ref": "$REGISTRY/" + n + "@" + d, "zone": zones[n]["zone"], "binaries": zones[n]["binaries"]}
m = {
    "schema": 1,
    "version": "$VERSION",
    "dryRun": "$PUBLISH" != "1",
    "source": {"repository": "$SOURCE_URL", "commit": "$COMMIT", "ref": "refs/tags/$VERSION" if "$PUBLISH" == "1" else None, "sourceDateEpoch": int("$SOURCE_DATE_EPOCH")},
    # What a verifier must expect on every image (cosign verify): exactly this certificate identity and issuer. Empty in a dry run (nothing is signed).
    "signer": {"identity": "$IDENTITY", "issuer": "$ISSUER" if "$PUBLISH" == "1" else "", "sbom": "BuildKit SBOM (SPDX) and SLSA provenance attestations inside each image index"},
    "images": images,
    # The input of the attestation allowlist (docs/runbooks/tee-broker.md). SIMULATED enclave: the measurement (PCR0) is SHA-384 over the party binary of this image
    # and the party's measured configuration (peer pins, caller pins, admin keys: different for every deployment), so it cannot be a build-time value. What IS
    # fixed here is its input, the image DIGEST, and the recipe: anyone computes the value with deploy/images/measure-release.py (it pulls the image by this digest).
    # Real Nitro (T7): PCR0 of the enclave image built from this digest, with the AWS tooling.
    "partyMeasurement": {"image": "mpc-party", "digest": images.get("mpc-party", {}).get("digest"), "binary": "/usr/local/bin/mpc-party", "pcr0": None,
                         "formula": "sha384(len8(binary) || binary || len8(config) || config), simulated enclave",
                         "recipe": "deploy/images/measure-release.py image --manifest <this file> --config <the party's measured config file>",
                         "status": "per deployment: the measured configuration is part of the input; two independent builds give the same binary, so the same measurement (checked by build.sh repro)"},
}
json.dump(m, open(out, "w"), indent=2, sort_keys=True); open(out, "a").write("\n")
PY
# The manifest must name every release image with a real digest, and nothing else (a -dev image in it would be a release of a development build).
python3 -I - "$MANIFEST" "${ONLY:-}" <<PY
import json, re, sys
m = json.load(open(sys.argv[1]))
want = {l.split(":")[0] for l in """$(qv_release_images)""".split()}
if sys.argv[2]:
    want = set(sys.argv[2].split())
got = set(m["images"])
assert got == want, "manifest images differ from the release set: missing %s, extra %s" % (sorted(want - got), sorted(got - want))
for n, i in m["images"].items():
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", i["digest"]) and set(i["digest"][7:]) != {"0"}, "bad digest for " + n
    assert i["ref"] == i["repository"] + "@" + i["digest"] and re.search(r"-dev|tee-?sim|softhsm", n) is None, "bad entry " + n
PY
echo "manifest: $MANIFEST" >&2

if [ "$PUBLISH" = 1 ]; then
  # Sign the manifest itself (keyless, same identity) so it can be checked without trusting the place it was downloaded from.
  cosign sign-blob --yes --bundle "$MANIFEST.sigstore.json" "$MANIFEST" >/dev/null
  echo "manifest signature bundle: $MANIFEST.sigstore.json" >&2
fi
echo "$OUT"
