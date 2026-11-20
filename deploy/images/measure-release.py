#!/usr/bin/env python3
"""The measurement (PCR0) a party build is allowed under, computed by anyone. SIMULATED enclave only: the real Nitro PCR0 is the hash of the enclave image
file (EIF), which needs the AWS tooling (task T7). Here PCR0 is what the simulation build's party computes about itself at start
(mpc-party/internal/attest.MeasureImage): SHA-384 over the party binary and the config file the party starts with, each preceded by its 8-byte big-endian length.
The config is the deployment's own measured configuration (peer pins, caller pins, admin keys), so one build has one measurement per party and deployment.
The formula is the same as `qv-attest-ca measure`; `selftest` checks it against the vector the Go test pins.

TWO BINARIES, NOT ONE. A simulated enclave runs the `-tags teesim` party (it has the mock attester). That is not the `mpc-party` of the released image, which has
no attester and refuses sealer.type "attested": the bytes differ, so the measurements differ. The simulated recipe measures the tee-sim build:

  docker buildx build -f deploy/images/Dockerfile --target bins --output type=local,dest=bins .
  measure-release.py binary --binary bins/mpc-party-teesim --config FILE      the simulated measurement (96 hex): what goes on the simulation's allowlist

`image` measures the PRODUCTION binary of a released image. Today that value is on no allowlist a simulation can use; it is the shape of what task T7 will
produce with the AWS tooling (PCR0 of the enclave image built from the release digest). It is kept so the release side has one tool, not as something to allow.

  measure-release.py selftest
  measure-release.py binary --binary FILE --config FILE                 prints the measurement (96 hex)
  measure-release.py image --manifest release-vX.json --config FILE     pulls the image BY DIGEST, takes /usr/local/bin/mpc-party, prints its measurement
  measure-release.py image --ref REPO@sha256:<64 hex> --config FILE
  measure-release.py same --binary A --binary B --config FILE           two builders' binaries: exit 1 unless the measurements are equal

`image` needs docker. A digest names the content, so the binary cannot differ for the same digest; that is the whole point of naming a digest, never a tag.
"""
import argparse, hashlib, json, os, re, struct, subprocess, sys, tempfile

BINARY_IN_IMAGE = "/usr/local/bin/mpc-party"
DIGEST_REF = re.compile(r"^[A-Za-z0-9./_:-]+@sha256:[0-9a-f]{64}$")
VECTOR = ("qv-binary", '{"role":"A"}', "d62171b1221a665b8e6c97d1be0c04a63f997fc5f96736ef7d22e224fc1bde82e02b6e9d6739b8326b32032b1949bf85")


def measure(binary: bytes, config: bytes) -> str:
    h = hashlib.sha384()
    for part in (binary, config):
        h.update(struct.pack(">Q", len(part)))
        h.update(part)
    return h.hexdigest()


def die(msg):
    print("measure-release: " + msg, file=sys.stderr)
    sys.exit(1)


def read(path):
    try:
        return open(path, "rb").read()
    except OSError as e:
        die("cannot read %s: %s" % (path, e))


def binary_of_image(ref):
    if not DIGEST_REF.match(ref) or set(ref.rsplit(":", 1)[1]) == {"0"}:
        die("%r is not REPOSITORY@sha256:<64 hex>: a tag names no content, use the digest" % ref)
    def docker(*a):
        r = subprocess.run(["docker", *a], capture_output=True)
        if r.returncode != 0:
            die("docker %s failed: %s" % (" ".join(a[:2]), r.stderr.decode().strip()))
        return r.stdout.decode().strip()
    docker("pull", "--quiet", ref)
    cid = docker("create", ref, "unused")  # never started
    try:
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "mpc-party")
            docker("cp", "%s:%s" % (cid, BINARY_IN_IMAGE), out)
            return read(out)
    finally:
        subprocess.run(["docker", "rm", "--force", cid], capture_output=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["selftest", "binary", "image", "same"])
    ap.add_argument("--binary", action="append")
    ap.add_argument("--config")
    ap.add_argument("--manifest")
    ap.add_argument("--ref")
    a = ap.parse_args()
    if a.cmd == "selftest":
        got = measure(VECTOR[0].encode(), VECTOR[1].encode())
        if got != VECTOR[2]:
            die("selftest: got %s, want %s" % (got, VECTOR[2]))
        print("ok: measurement formula matches the vector pinned in mpc-party/internal/attest")
        return
    if not a.config:
        die("--config is required")
    cfg = read(a.config)
    if a.cmd == "binary":
        if not a.binary or len(a.binary) != 1:
            die("binary: exactly one --binary")
        print(measure(read(a.binary[0]), cfg))
    elif a.cmd == "same":
        if not a.binary or len(a.binary) != 2:
            die("same: two --binary")
        m = [measure(read(b), cfg) for b in a.binary]
        print(m[0])
        if m[0] != m[1]:
            die("the two builds have different measurements:\n  %s\n  %s" % (m[0], m[1]))
    else:
        ref = a.ref
        if a.manifest:
            try:
                ref = json.load(open(a.manifest))["images"]["mpc-party"]["ref"]
            except (OSError, ValueError, KeyError) as e:
                die("cannot read the mpc-party image from %s: %s" % (a.manifest, e))
        if not ref:
            die("image: --manifest or --ref")
        print(measure(binary_of_image(ref), cfg))


main()
