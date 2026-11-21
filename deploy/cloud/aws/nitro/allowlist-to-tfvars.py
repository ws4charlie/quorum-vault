#!/usr/bin/env python3
"""Turn the signed attestation allowlist into the `allowed_images` variable of the Terraform module modules/nitro-enclave (the KMS key policy's PCR conditions).

  allowlist-to-tfvars.py --party A [--now 2026-12-01T00:00:00Z] < allowlist.json > party-a.auto.tfvars.json

One source of truth: the same entries (PCR0 and the further PCRs of an entry) that the broker enforces become the conditions KMS enforces, so the two cannot
disagree about which image may run. What it does NOT do: verify the signatures. Run `qv-attest-broker allowlist show -in allowlist.json -operators broker.json` first
(it exits non-zero unless enough operators signed) and only then feed the file here; the script refuses a file with no signatures at all as a guard against the
obvious slip.

Rules (the broker's, as far as a static policy can follow them):
  - only this party's entries; an entry with status "revoked" removes every entry of the same PCR0;
  - an entry whose not_after has passed, or whose not_before has not come, is left out (a KMS key policy has no clock: the file is regenerated and applied to
    follow time, where the broker follows it by itself; the limits page says so);
  - an entry without PCRs other than PCR0 is allowed and gives a policy on PCR0 alone, which is weaker than a Nitro entry with PCR1, PCR2 and PCR8: a warning is
    printed to stderr;
  - nothing active left is an error: a key policy with no PCR condition is never written.
"""
import argparse, json, re, sys
from datetime import datetime, timezone

HEX96 = re.compile(r"^[0-9a-f]{96}$")


def parse_time(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def build(lst, party, now):
    if not lst.get("signatures"):
        raise ValueError("the allowlist has no signatures: verify it with `qv-attest-broker allowlist show` first")
    entries = [e for e in lst.get("entries", []) if e.get("party") == party]
    revoked = {e["measurement"].lower() for e in entries if e.get("status") == "revoked"}
    images, warnings = [], []
    for e in entries:
        m = e["measurement"].lower()
        if e.get("status") == "revoked" or m in revoked:
            continue
        nb = parse_time(e["not_before"])
        na = parse_time(e["not_after"]) if e.get("not_after") else None
        if nb > now or (na is not None and na < now):
            continue
        pcrs = {"0": m}
        for k, v in (e.get("pcrs") or {}).items():
            pcrs[str(int(k))] = v.lower()
        for k, v in pcrs.items():
            if not HEX96.match(v) or set(v) == {"0"}:
                raise ValueError("PCR%s of %s is not a non-zero SHA-384 value" % (k, m[:12]))
        if len(pcrs) == 1:
            warnings.append("entry %s has no PCRs besides PCR0: the key policy will check the image hash only" % (e.get("version") or m[:12]))
        name = re.sub(r"[^A-Za-z0-9_.-]", "-", e.get("version") or m[:12])[:40]
        images.append({"name": name, "pcrs": dict(sorted(pcrs.items(), key=lambda kv: int(kv[0])))})
    if not images:
        raise ValueError("no active entry for party %s at %s: a key policy without a PCR condition is never written" % (party, now.strftime("%Y-%m-%dT%H:%M:%SZ")))
    names = [i["name"] for i in images]
    if len(set(names)) != len(names):
        raise ValueError("two active entries have the same version name; give each release its own version")
    return {"allowed_images": images}, warnings


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--party", required=True)
    ap.add_argument("--now", help="RFC 3339 UTC, default the current time")
    ap.add_argument("--input", help="the signed allowlist (default: stdin)")
    a = ap.parse_args(argv)
    now = parse_time(a.now) if a.now else datetime.now(timezone.utc)
    try:
        out, warns = build(json.load(open(a.input) if a.input else sys.stdin), a.party, now)
    except (ValueError, KeyError) as e:
        print("allowlist-to-tfvars: %s" % e, file=sys.stderr)
        return 1
    for w in warns:
        print("allowlist-to-tfvars: warning: %s" % w, file=sys.stderr)
    json.dump(out, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
