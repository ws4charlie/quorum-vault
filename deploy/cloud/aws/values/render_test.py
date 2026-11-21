#!/usr/bin/env python3
"""Renders each chart with its AWS values (helm template) and checks the NetworkPolicies against paths.json, the list of every cross-domain path of the design:
every path has the allow rule on both ends (all endpoint interfaces, the ports), and nothing else is open. Needs helm and PyYAML (both required: missing = failure).
Run from anywhere: python3 deploy/cloud/aws/values/render_test.py"""
import json, pathlib, re, subprocess, sys, tempfile
import yaml

here = pathlib.Path(__file__).resolve().parent
repo = here.parents[3]
helm_dir, ci = repo / "deploy/helm", repo / "ci/helm"
paths = [p for p in json.loads((here.parent / "paths.json").read_text())["paths"] if not p["optional"]]
cidrs = json.loads((here.parent / "cidrs.json").read_text())
ZONES = 3

# Known chart gaps (chart change listed for the lead). The test FAILS when a gap closes, so the entry gets removed and the rule is enforced.
# (path id, port): why
KNOWN_GAPS = {
    ("gateway-heads", 9093): "qv-signing-core opens one Kafka port (network.kafka.port)",
    ("gateway-heads", 9094): "qv-signing-core opens one Kafka port (network.kafka.port)",
    ("business-kafka-link", 9093): "qv-business signingLink opens one Kafka port (network.kafka.port)",
    ("business-kafka-link", 9094): "qv-business signingLink opens one Kafka port (network.kafka.port)",
}

def second(domain): return int(cidrs[domain].split(".")[1])
def fake_ip(pid, i): return f"10.{100 + [p['id'] for p in paths].index(pid)}.0.{i + 1}"
def fake_hsm(d, i): return f"10.{second(d)}.250.{i + 1}"
def fake_subnet(d, i): return f"10.{second(d)}.{16 * i}.0/20"

def fill(m):
    t = m.group(1)
    mm = re.fullmatch(r"([a-z-]+)\.endpoint_ips\.([a-z0-9-]+)\.(\d+)", t)
    if mm: return fake_ip(mm.group(2), int(mm.group(3)))
    mm = re.fullmatch(r"([a-z-]+)\.hsm\.ips\.(\d+)", t)
    if mm: return fake_hsm(mm.group(1), int(mm.group(2)))
    mm = re.fullmatch(r"([a-z-]+)\.private_subnet_cidrs\.(\d+)", t)
    if mm: return fake_subnet(mm.group(1), int(mm.group(2)))
    mm = re.fullmatch(r"([a-z-]+) VPC range( from cidrs.json)?", t)
    if mm: return cidrs[mm.group(1)]
    return "x-" + re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-")

def load(name, drop_network=False):
    d = yaml.safe_load(open(name))
    if drop_network: d.pop("network", None)   # the CI inputs carry made-up addresses; only the AWS file may open anything
    return d

def helm(release, chart, ns, files, sets=()):
    with tempfile.TemporaryDirectory() as td:
        args = ["helm", "template", release, str(helm_dir / chart), "-n", ns]
        for i, (f, drop) in enumerate(files):
            t = pathlib.Path(td) / f"v{i}.yaml"
            if f.suffix == ".yaml" and f.parent == here:
                t.write_text(re.sub(r"<([^>\n]+)>", fill, f.read_text()))
            else:
                t.write_text(yaml.safe_dump(load(f, drop)))
            args += ["-f", str(t)]
        for s in sets: args += ["--set", s]
        r = subprocess.run(args, capture_output=True, text=True)
        if r.returncode: sys.exit(f"helm template {release} failed:\n{r.stderr}")
        return [d for d in yaml.safe_load_all(r.stdout) if d]

def policies(objs): return [d for d in objs if d.get("kind") == "NetworkPolicy"]

def cidr_list(peers): return [p["ipBlock"]["cidr"] for p in peers or [] if "ipBlock" in p]

def egress_rules(pols):  # (to-cidrs, ports)
    out = []
    for p in pols:
        for r in p["spec"].get("egress", []) or []:
            out.append((cidr_list(r.get("to")), [x["port"] for x in r.get("ports", [])], r.get("to")))
    return out

def ingress_rules(pols):
    out = []
    for p in pols:
        for r in p["spec"].get("ingress", []) or []:
            out.append((cidr_list(r.get("from")), [x["port"] for x in r.get("ports", [])], r.get("from"), p))
    return out

bad = []
def check(cond, msg):
    if not cond: bad.append(msg)

pvals = [(helm_dir / "qv-party/values.yaml", False), (ci / "ci-party-values.yaml", True), (ci / "ci-party-digests.yaml", True)]
rel = {
    "business": helm("qv-business", "qv-business", "qv-business",
                     [(helm_dir / "qv-business/values.yaml", False), (ci / "ci-digests.yaml", True), (here / "business.yaml", False)]),
    "signing-core": helm("qv-signing", "qv-signing-core", "qv-signing",
                         [(helm_dir / "qv-signing-core/values.yaml", False), (ci / "signing-core-ci.yaml", True), (here / "signing-core.yaml", False)]),
}
for r, ns in (("a", "qv-signing"), ("b", "qv-party-b"), ("c", "qv-party-c")):
    rel["party-" + r] = helm("qv-party-" + r, "qv-party", ns, pvals + [(here / f"party-{r}.yaml", False)], sets=[f"role={r.upper()}"])
pol = {k: policies(v) for k, v in rel.items()}

# who dials which path (the egress side) and who receives it (the ingress side)
dialer = {"gateway-jobs-db": "signing-core", "gateway-heads": "signing-core", "gateway-party-b-caller": "signing-core", "gateway-party-c-caller": "signing-core",
          "a-party-b-peer": "party-a", "a-party-c-peer": "party-a", "b-party-c-peer": "party-b", "cosigner-b-heads": "party-b", "cosigner-c-heads": "party-c"}
check(sorted(dialer) == sorted(p["id"] for p in paths), f"every non-optional path needs a dialer in this test: {sorted(set(p['id'] for p in paths) ^ set(dialer))}")

for p in paths:
    ips = [fake_ip(p["id"], i) + "/32" for i in range(ZONES)]
    rules = [r for r in egress_rules(pol[dialer[p["id"]]]) if all(ip in r[0] for ip in ips)]
    check(rules, f"{p['id']}: no egress rule of {dialer[p['id']]} names all {ZONES} endpoint addresses")
    open_ports = {x for r in rules for x in r[1]}
    for port in p["ports"]:
        if port in open_ports:
            check((p["id"], port) not in KNOWN_GAPS, f"{p['id']}:{port} is open now: remove it from KNOWN_GAPS")
        else:
            check((p["id"], port) in KNOWN_GAPS, f"{p['id']}: port {port} not opened by the egress rule")

# provider ends
for dom, key in (("party-b", "b"), ("party-c", "c")):
    subs = sorted(fake_subnet(dom, i) for i in range(ZONES))
    for purpose, ports in (("party-caller", [7001]), ("party-peer", [7003])):
        rs = [r for r in ingress_rules(pol["party-" + key]) if r[3]["metadata"].get("annotations", {}).get("quorumvault.io/ingress-purpose") == purpose]
        check(rs, f"{dom}: no {purpose} ingress policy")
        for cl, pt, frm, _ in rs:
            check(all(s in cl for s in subs), f"{dom}: {purpose} ingress does not name every NLB subnet {subs}: {cl}")
            check(sorted(pt) == ports, f"{dom}: {purpose} ingress ports {pt}")
sub_b = sorted(fake_subnet("business", i) for i in range(ZONES))
link = [r for r in ingress_rules(pol["business"]) if r[3]["metadata"].get("annotations", {}).get("quorumvault.io/ingress-purpose") == "signing-link"]
check(len(link) == 2, "business: two signing-link policies (Postgres, Kafka)")
for cl, pt, frm, pl in link:
    check(sorted(cl) == sub_b, f"business signing link sources {cl}")
for port in (9093, 9094):
    open_now = any(port in r[1] for r in link)
    check(open_now == (("business-kafka-link", port) not in KNOWN_GAPS), f"business Kafka link port {port} state differs from KNOWN_GAPS")
check(any(5432 in r[1] for r in link), "business: signing link opens Postgres 5432")
# party A's caller port admits the gateway (same cluster)
a_rs = [r for r in ingress_rules(pol["party-a"]) if r[3]["metadata"].get("annotations", {}).get("quorumvault.io/ingress-purpose") == "party-caller"]
check(any(any("podSelector" in x and x["podSelector"]["matchLabels"].get("app.kubernetes.io/component") == "gateway" for x in (r[2] or [])) for r in a_rs), "party A: the caller port does not admit the gateway pods")
gw = [r for r in egress_rules(pol["signing-core"]) if 7001 in r[1]]
check(gw, "gateway: no egress to party A's caller port")

# nothing else open
RFC1918 = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
allowed = {
    "signing-core": {fake_ip(p["id"], i) + "/32" for p in paths if dialer[p["id"]] == "signing-core" for i in range(ZONES)},
    "party-a": {fake_ip(p["id"], i) + "/32" for p in paths if dialer[p["id"]] == "party-a" for i in range(ZONES)} | {fake_hsm("signing-core", i) + "/32" for i in range(2)},
    "party-b": {fake_ip(p["id"], i) + "/32" for p in paths if dialer[p["id"]] == "party-b" for i in range(ZONES)} | {fake_hsm("party-b", i) + "/32" for i in range(2)} | {fake_subnet("party-b", i) for i in range(ZONES)},
    "party-c": {fake_ip(p["id"], i) + "/32" for p in paths if dialer[p["id"]] == "party-c" for i in range(ZONES)} | {fake_hsm("party-c", i) + "/32" for i in range(2)} | {fake_subnet("party-c", i) for i in range(ZONES)},
}
for k, pl in pol.items():
    for np_ in pl:
        name = np_["metadata"]["name"]
        for direction in ("ingress", "egress"):
            for r in np_["spec"].get(direction, []) or []:
                peers = r.get("from" if direction == "ingress" else "to")
                if peers is None:
                    check(False, f"{k}/{name}: a {direction} rule without peers is open to everyone")
                    continue
                for c in cidr_list(peers):
                    if k == "business":
                        ok = c in {fake_subnet("business", i) for i in range(ZONES)} or c == "0.0.0.0/0"   # the chart's default IdP, chain and archive rules (public addresses, private ranges excepted)
                        if c == "0.0.0.0/0":
                            ex = {e for x in peers if x.get("ipBlock", {}).get("cidr") == c for e in x["ipBlock"].get("except", [])}
                            ok = RFC1918 <= ex
                    else:
                        ok = c in allowed[k]
                    check(ok, f"{k}/{name}: {direction} to or from {c} is not on the list of the design's paths")

print("\n".join(bad) or f"render_test: ok ({len(paths)} paths, 5 releases rendered)")
sys.exit(1 if bad else 0)
