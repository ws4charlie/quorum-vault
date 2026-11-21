#!/usr/bin/env python3
"""Compare the PCRs a probe enclave reported with the PCRs eif-build.sh printed for the same image, on the PARENT.

  check-probe-report.py --report report.json --pcrs probe-out/pcrs.json

The comparison cannot live inside the probe image: that image is what the PCRs measure, so an expected value written into it would change the value it names.
Exit 0 only if every PCR of the build (PCR0, PCR1, PCR2, and PCR8 when the image was signed) is in the report and equal, and the report says the document
verified, was not a debug document and (when present) that its KMS round trip gave equal keys.
"""
import argparse, json, sys


def check(report, pcrs):
    problems = []
    if not report.get("verified"):
        problems.append("the document did not verify: %s" % report.get("verify_error", "?"))
    if report.get("debug"):
        problems.append("the document is a debug-mode document")
    got = {k: v.lower() for k, v in (report.get("pcrs") or {}).items()}
    if not pcrs:
        problems.append("the build output has no PCRs")
    for name, want in sorted(pcrs.items()):
        n = name[3:] if name.startswith("PCR") else name
        if got.get(n) != want.lower():
            problems.append("PCR%s: build %s, enclave %s" % (n, want[:16] + "...", (got.get(n) or "absent")[:16]))
    k = report.get("kms")
    if k is not None and (not k.get("keys_equal") or k.get("error")):
        problems.append("KMS round trip: %s" % (k.get("error") or "keys differ"))
    return problems


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", required=True)
    ap.add_argument("--pcrs", required=True)
    a = ap.parse_args(argv)
    problems = check(json.load(open(a.report)), json.load(open(a.pcrs)))
    for p in problems:
        print("check-probe-report: " + p, file=sys.stderr)
    if not problems:
        print("check-probe-report: every PCR of the build is in the enclave's document and equal")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
