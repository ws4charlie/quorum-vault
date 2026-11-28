#!/usr/bin/env python3
"""Check the documentation: the top-level *.md files, docs/**/*.md, and every README*.md under deploy/ and ci/.
  - every relative link and image resolves, and its #anchor names a heading (or an id) of the target page;
  - every repository path written in backticks (`internal/pki/catalog.go`, `deploy/images/`) exists;
  - each English concept page in docs/ has a Chinese twin in docs/zh/ with the same number of sections.
Run from anywhere: python3 docs/check_links.py   (exit 1 on any problem)"""
import pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LINK = re.compile(r'(?<!\\)\]\(([^)\s]+)\)|<(?:a|img)[^>]*?(?:href|src)="([^"]+)"')
CODE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
# a backtick text is checked as a path when it starts with a top-level entry of the repository, or names a file of a kind the repository holds
TOP = {p.name for p in ROOT.iterdir()}
EXT = re.compile(r"\.(md|go|sh|py|ya?ml|json|tf|tpl|sql|toml|mod|env|txt|html|js|css|png|svg)$")
PATH = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.@-]+)*/?$")
# made by a build or a run, never committed: named in the docs, absent from a fresh checkout
GENERATED = ("data/", "bin/", "mpc-party/.deps")
# a page whose backtick paths are of another tree (a historical spike) opts out of the path check with this comment followed by its reason in
# parentheses; a marker without a reason is an error. Used by: docs/spikes/p5a-cbmpc.md only.
NO_PATHS = "<!-- check_links: no-paths"

tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
# directory names anywhere in the repository: `smoke/`, `modules/irsa/` start with one, so they are checked as paths too
# such a path must be the tail of a tracked path (`modules/nitro-enclave` of deploy/cloud/aws/). Not paths: a catalog identity zone/service
# (`business/gateway-link`, internal/pki), and a path of another repository written `<repo>:<path>` (`cb-mpc:src/cbmpc/api/schnorr2pc.cpp`).
KNOWN = {d for t in tracked for d in t.split("/")[:-1]} - {"business", "signing"}
TAILS = {"/".join(t.split("/")[i:j]) for t in tracked for i in range(len(t.split("/"))) for j in range(i + 1, len(t.split("/")) + 1)}
files = sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").rglob("*.md"))
files += sorted(ROOT / p for p in tracked if re.match(r"(deploy|ci)/(.*/)?README[^/]*\.md$", p))
bad = []


def slug(heading):
    """GitHub's anchor of a heading: markup dropped, lower case, punctuation removed, spaces to hyphens."""
    h = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # [text](url) -> text
    h = re.sub(r"<[^>]+>", "", h).replace("`", "").strip().lower()
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")


anchors_cache = {}


def anchors(path):
    if path not in anchors_cache:
        text = re.sub(r"```.*?```", "", path.read_text(encoding="utf-8"), flags=re.S)
        seen, out = {}, set()
        for m in re.finditer(r"^#{1,6}\s+(.+?)\s*#*\s*$", text, flags=re.M):
            s = slug(m.group(1))
            n = seen.get(s, 0)
            seen[s] = n + 1
            out.add(s if n == 0 else f"{s}-{n}")
        out |= set(re.findall(r'<a\s+(?:id|name)="([^"]+)"', text))
        anchors_cache[path] = out
    return anchors_cache[path]


for f in files:  # invalid UTF-8 or a replacement character (a damaged character)
    try:
        if "�" in f.read_bytes().decode("utf-8"):
            bad.append(f"{f.relative_to(ROOT)}: contains a replacement character (a damaged character)")
    except UnicodeDecodeError:
        bad.append(f"{f.relative_to(ROOT)}: not valid UTF-8")
for f in files:
    rel = f.relative_to(ROOT)
    text = re.sub(r"```.*?```", "", f.read_text(encoding="utf-8"), flags=re.S)
    for m in LINK.finditer(text):
        t = m.group(1) or m.group(2)
        if re.match(r"[a-z]+:", t):
            continue
        target, _, frag = t.partition("#")
        dest = (f.parent / target) if target else f
        if not dest.exists():
            bad.append(f"{rel}: broken link {target}")
        elif frag and dest.suffix == ".md" and frag not in anchors(dest):
            bad.append(f"{rel}: broken anchor {t}")
    if NO_PATHS in text and not re.search(re.escape(NO_PATHS) + r" \([^)]+\) -->", text):
        bad.append(f"{rel}: a check_links no-paths marker without a reason")
    for m in CODE.finditer(text) if NO_PATHS not in text else ():
        p = re.sub(r"(:\d+(-\d+)?(,\d+)*|#L\d+(-L\d+)?)$", "", m.group(1).strip())  # file.go:12, file.go#L5 -> file.go
        if not PATH.match(p) or "/" not in p and not EXT.search(p) or p.startswith(".") or "X.Y.Z" in p or p.startswith(GENERATED):
            continue
        g = re.match(r"^(.+)\.[A-Z]\w*$", p)  # a Go identifier, package.Name: the package directory must exist
        if g and "/" in p and (ROOT / g.group(1)).is_dir():
            continue
        if p.split("/")[0] not in TOP | KNOWN and not ("/" in p and EXT.search(p)):
            continue  # an image name, a URL path, a Vault path: not a file of this repository
        if not ((ROOT / p).exists() or (f.parent / p).exists() or p.split("/")[0] not in TOP and p.rstrip("/") in TAILS):
            bad.append(f"{rel}: missing path `{m.group(1)}`")

docs = ROOT / "docs"
for en in sorted(docs.glob("*.md")):
    zh = docs / "zh" / en.name
    if not zh.exists():
        bad.append(f"{en.relative_to(ROOT)}: no Chinese twin")
        continue
    h = lambda p: len(re.findall(r"^## ", p.read_text(encoding="utf-8"), flags=re.M))
    if h(en) != h(zh):
        bad.append(f"{en.name}: {h(en)} sections in English, {h(zh)} in Chinese")
for zh in sorted((docs / "zh").glob("*.md")):
    if not (docs / zh.name).exists():
        bad.append(f"docs/zh/{zh.name}: no English page")
print("\n".join(bad) or "ok")
sys.exit(1 if bad else 0)
