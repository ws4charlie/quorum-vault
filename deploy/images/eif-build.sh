#!/usr/bin/env bash
# Build the enclave image file (EIF) of one MPC party from a RELEASED party image, and print its PCRs.
#
#   deploy/images/eif-build.sh --party-image REPO@sha256:<64 hex> --config-dir DIR --out DIR [--sign-key FILE --sign-cert FILE] [--epoch SECONDS]
#
# Needs: Linux (or Docker Desktop), docker with buildx >= 0.13 (rewrite-timestamp), network to pull the images. It does NOT need an enclave-capable
# host, an AWS account or credentials: nitro-cli only reads the image and writes the file. Output in DIR:
#   party.eif        the enclave image (not committed anywhere: it is a build output)
#   pcrs.json        the PCRs nitro-cli printed (PCR0, PCR1, PCR2 and PCR8 when signed)
#   build-info.json  what the PCRs depend on: input image digest, config digest, SOURCE_DATE_EPOCH, nitro-cli version, hashes of its kernel blobs, architecture
# Next: deploy/cloud/aws/nitro/nitro-cli-to-allowlist.py < DIR/pcrs.json   (the allowlist command), then the key policy (docs/runbooks/nitro-first-run.md).
#
# Reproducible: the same party image digest, the same config directory content, the same --epoch, the same nitro-cli package and the same architecture
# give the same PCRs, whoever builds (shown by `eif-build.sh --repro`, and in docs/runbooks/nitro-first-run.md). The file times matter: PCR0 and PCR2 changed when
# only SOURCE_DATE_EPOCH changed in the test, so the epoch is an input, recorded in build-info.json, and the layers' times are rewritten to it.
#   --repro   build twice from scratch (no cache) and fail unless the PCRs are equal
#   --probe   make the first-hardware probe image instead of a party: the same released image, entry point `mpc-party nitro-probe -config /etc/qv/config/probe.json`
#             (config dir holds probe.json). Its PCRs are NOT the party's: its configuration differs. docs/runbooks/nitro-first-run.md says when to use it.
set -euo pipefail
cd "$(dirname "$0")/../.."

party="" cfg="" out="" key="" cert="" epoch="" repro=0 probe=0
while [ $# -gt 0 ]; do
  case "$1" in
    --party-image) party="$2"; shift 2 ;;
    --config-dir) cfg="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --sign-key) key="$2"; shift 2 ;;
    --sign-cert) cert="$2"; shift 2 ;;
    --epoch) epoch="$2"; shift 2 ;;
    --repro) repro=1; shift ;;
    --probe) probe=1; shift ;;
    *) echo "eif-build: unknown argument $1" >&2; exit 2 ;;
  esac
done
die() { echo "eif-build: $*" >&2; exit 1; }
[[ "$party" =~ ^[A-Za-z0-9./_:-]+@sha256:[0-9a-f]{64}$ ]] || die "--party-image must be REPOSITORY@sha256:<64 hex>: a tag names no content"
[[ "$party" =~ @sha256:0{64}$ ]] && die "an all-zero digest is a placeholder"
want_cfg=party.json; [ "$probe" = 1 ] && want_cfg=probe.json
[ -d "$cfg" ] && [ -f "$cfg/$want_cfg" ] || die "--config-dir must hold $want_cfg"
[ -n "$out" ] || die "--out is required"
[ -z "$key$cert" ] || { [ -n "$key" ] && [ -n "$cert" ]; } || die "--sign-key and --sign-cert go together"
: "${epoch:=$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
[[ "$epoch" =~ ^[0-9]+$ ]] || die "--epoch must be seconds"
mkdir -p "$out"; out="$(cd "$out" && pwd)"
cfg="$(cd "$cfg" && pwd)"

arch="$(docker info --format '{{.Architecture}}')"
builder="qv-eif-builder:${arch}"
docker buildx build --provenance=false --sbom=false --load -t "$builder" -f deploy/images/Dockerfile.eif-builder deploy/images >/dev/null

one() { # one <tag> <dir>
  local tag="$1" dir="$2" ctx; ctx="$(mktemp -d)"
  mkdir -p "$ctx/config"; cp -R "$cfg/." "$ctx/config/"; cp deploy/images/Dockerfile.eif "$ctx/Dockerfile"
  if [ "$probe" = 1 ]; then
    grep -v '^ENTRYPOINT' deploy/images/Dockerfile.eif > "$ctx/Dockerfile"
    echo 'ENTRYPOINT ["/usr/local/bin/mpc-party", "nitro-probe", "-config", "/etc/qv/config/probe.json"]' >> "$ctx/Dockerfile"
  fi
  docker buildx build --no-cache --provenance=false --sbom=false --build-arg "PARTY_IMAGE=$party" --build-arg "SOURCE_DATE_EPOCH=$epoch" \
    --output "type=docker,name=$tag,rewrite-timestamp=true" "$ctx" >/dev/null
  rm -rf "$ctx"
  local sign=()
  if [ -n "$key" ]; then sign=(--private-key /sign/key.pem --signing-certificate /sign/cert.pem); fi
  local mounts=(-v /var/run/docker.sock:/var/run/docker.sock -v "$dir:/out")
  [ -z "$key" ] || mounts+=(-v "$key:/sign/key.pem:ro" -v "$cert:/sign/cert.pem:ro")
  docker run --rm "${mounts[@]}" "$builder" nitro-cli build-enclave --docker-uri "$tag" --output-file /out/party.eif ${sign[@]+"${sign[@]}"} > "$dir/nitro-cli.out"
  python3 -I - "$dir/nitro-cli.out" "$dir/pcrs.json" <<'PY'
import json, sys
t = open(sys.argv[1]).read()
m = json.JSONDecoder().raw_decode(t[t.index("{"):])[0]["Measurements"]
json.dump({k: v for k, v in m.items() if k.startswith("PCR")}, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PY
}

if [ "$repro" = 1 ]; then
  a="$(mktemp -d)"; b="$(mktemp -d)"
  one "qv-eif-input:repro-a" "$a"; one "qv-eif-input:repro-b" "$b"
  cmp -s "$a/pcrs.json" "$b/pcrs.json" || { echo "eif-build: the two builds measure differently:"; diff "$a/pcrs.json" "$b/pcrs.json" || true; exit 1; }
  echo "eif-build: two from-scratch builds give the same PCRs"
  cp "$a/party.eif" "$a/pcrs.json" "$a/nitro-cli.out" "$out/"
else
  one "qv-eif-input:build" "$out"
fi

blobs="$(docker run --rm "$builder" sh -c 'cd /usr/share/nitro_enclaves/blobs && sha256sum *' | python3 -I -c 'import sys,json; print(json.dumps({l.split()[1]: l.split()[0] for l in sys.stdin}))')"
python3 -I - "$out/build-info.json" "$party" "$epoch" "$arch" "$blobs" "$(docker run --rm "$builder" nitro-cli --version)" "$cfg" <<'PY'
import hashlib, json, os, sys
p = sys.argv
h = hashlib.sha256()
for root, _, files in sorted(os.walk(p[7])):
    for f in sorted(files):
        path = os.path.join(root, f)
        h.update(os.path.relpath(path, p[7]).encode() + b"\0" + hashlib.sha256(open(path, "rb").read()).digest())
json.dump({"partyImage": p[2], "sourceDateEpoch": int(p[3]), "architecture": p[4], "nitroCliBlobsSha256": json.loads(p[5]), "nitroCli": p[6], "configTreeSha256": h.hexdigest()}, open(p[1], "w"), indent=2, sort_keys=True)
PY
echo "eif-build: wrote $out/party.eif, pcrs.json, build-info.json"
cat "$out/pcrs.json"
