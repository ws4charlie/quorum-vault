#!/usr/bin/env python3
"""Every key in the AWS values files must exist in the chart's own values.yaml (a typo would otherwise be ignored by Helm). Run: python3 values_test.py"""
import pathlib, sys
import yaml  # required: a missing PyYAML is an error, never a pass (pinned in ../requirements.txt)
here = pathlib.Path(__file__).parent
charts = here / "../../../helm"
pairs = {"business": "qv-business", "signing-core": "qv-signing-core", "party-a": "qv-party", "party-b": "qv-party", "party-c": "qv-party"}
def walk(v, ref, path, bad):
    if not isinstance(v, dict): return
    for k, x in v.items():
        if not isinstance(ref, dict) or k not in ref:
            # free-form maps (annotations, labels) are fine
            if path and path[-1] in ("annotations", "labels", "matchLabels"): continue
            bad.append(".".join(path + [k])); continue
        walk(x, ref[k], path + [k], bad)
bad = []
for f, c in pairs.items():
    vals = yaml.safe_load(open(here / f"{f}.yaml").read().replace("<", "X").replace(">", "X"))
    ref = yaml.safe_load(open(charts / c / "values.yaml"))
    b = []; walk(vals, ref, [], b); bad += [f"{f}: {x}" for x in b]
print("\n".join(bad) or "values_test: ok"); sys.exit(1 if bad else 0)
