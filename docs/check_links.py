#!/usr/bin/env python3
"""Check that every relative link and image in README*.md and docs/**/*.md resolves,
and that each English concept page has a Chinese twin with the same number of sections.
Run from anywhere: python3 docs/check_links.py   (exit 1 on any problem)"""
import pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LINK = re.compile(r'(?<!\\)\]\(([^)\s]+)\)|<(?:a|img)[^>]*?(?:href|src)="([^"]+)"')
bad = []
files = sorted(ROOT.glob("README*.md")) + sorted((ROOT / "docs").rglob("*.md"))
for f in files:
    text = re.sub(r"```.*?```", "", f.read_text(encoding="utf-8"), flags=re.S)
    for m in LINK.finditer(text):
        t = (m.group(1) or m.group(2)).split("#")[0]
        if not t or re.match(r"[a-z]+:", t):
            continue
        if not (f.parent / t).exists():
            bad.append(f"{f.relative_to(ROOT)}: broken link {t}")

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
