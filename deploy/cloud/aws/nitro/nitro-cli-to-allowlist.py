#!/usr/bin/env python3
"""Turn the output of `nitro-cli build-enclave` into the allowlist command that puts that image on the signed allowlist.

  nitro-cli-to-allowlist.py --party A --version v1.4.0 [--current current.json --out next.json] < build-output.json

`nitro-cli build-enclave` prints (to stdout, after some progress lines) a JSON object:
  {"Measurements": {"HashAlgorithm": "Sha384 { ... }", "PCR0": "<96 hex>", "PCR1": "...", "PCR2": "...", "PCR8": "..."}}
PCR8 is there only when the image was signed (--private-key and --signing-certificate). (AWS Nitro Enclaves user guide, page "nitro-cli build-enclave")
The script prints one line, `qv-attest-broker allowlist add ... -measurement PCR0 -pcr 1=... -pcr 2=... [-pcr 8=...]`, and refuses anything that is not a
clean Nitro measurement: a missing PCR0, a value that is not 96 hex characters, an all-zero value (a debug-mode build reports zeros).
"""
import argparse, json, re, shlex, sys

HEX96 = re.compile(r"^[0-9a-fA-F]{96}$")


def extract(text):
    """The JSON object of the output: the progress lines before it are not JSON."""
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in the input")
    obj, _ = json.JSONDecoder().raw_decode(text[start:])
    m = obj.get("Measurements")
    if not isinstance(m, dict):
        raise ValueError("no Measurements object")
    return m


def pcrs(m):
    out = {}
    for k, v in m.items():
        mm = re.fullmatch(r"PCR(\d+)", k)
        if not mm:
            continue
        if not isinstance(v, str) or not HEX96.match(v):
            raise ValueError("%s is not 96 hex characters" % k)
        if set(v) == {"0"}:
            raise ValueError("%s is all zero: that is what a debug-mode enclave reports, never allowlist it" % k)
        out[int(mm.group(1))] = v.lower()
    if 0 not in out:
        raise ValueError("no PCR0")
    return out


def command(party, version, p, current=None, out=None):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", party):
        raise ValueError("bad party")
    if not re.fullmatch(r"[A-Za-z0-9._+-]{1,64}", version):
        raise ValueError("bad version")
    a = ["qv-attest-broker", "allowlist", "add", "-in", current or "current.json", "-out", out or "next.json",
         "-party", party, "-measurement", p[0], "-version", version]
    for n in sorted(k for k in p if k != 0):
        a += ["-pcr", "%d=%s" % (n, p[n])]
    return " ".join(shlex.quote(x) for x in a)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--party", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--current")
    ap.add_argument("--out")
    ap.add_argument("--input", help="the build output (default: stdin)")
    a = ap.parse_args(argv)
    text = open(a.input).read() if a.input else sys.stdin.read()
    try:
        print(command(a.party, a.version, pcrs(extract(text)), a.current, a.out))
    except ValueError as e:
        print("nitro-cli-to-allowlist: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
