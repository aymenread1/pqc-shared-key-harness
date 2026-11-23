#!/usr/bin/env python3
"""Collect the code context a reviewer needs to triage each non-test finding of the prevalence scan.

For every finding: the declaration, every line of the same file that uses the field, and automatic
hints (synchronized methods/blocks, clone() of a prototype, ThreadLocal, lock objects).
Output: <out>/triage_context.jsonl. The verdict itself is assigned by a human reviewer (triage.csv).
Author: Ayman Alsadig Mohamed Suliman. License: MIT.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

out = sys.argv[1] if len(sys.argv) > 1 else "prevalence/out"
fs = [json.loads(l) for l in open(os.path.join(out, "findings.jsonl"))]
fs = [f for f in fs if not f["test"] and f["severity"] in ("HIGH", "MEDIUM")]
by_repo = {}
for f in fs:
    by_repo.setdefault((f["repo"], f["commit"]), []).append(f)

NAME = re.compile(r"'(\w+)'")
res = []
for (repo, commit), items in sorted(by_repo.items()):
    d = tempfile.mkdtemp()
    try:
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"https://github.com/{repo}", d], check=True, timeout=600)
        for f in items:
            p = os.path.join(d, f["file"])
            src = open(p, encoding="utf-8", errors="replace").read().splitlines()
            name = NAME.search(f["message"]).group(1)
            use = [(i + 1, l.strip()[:160]) for i, l in enumerate(src) if re.search(r"\b" + re.escape(name) + r"\b", l)]
            text = "\n".join(src)
            hints = {
                "synchronizedMethodsInFile": len(re.findall(r"\bsynchronized\s+[\w<>\[\], ]+\s+\w+\s*\(", text)),
                "synchronizedOnField": bool(re.search(r"synchronized\s*\(\s*(this\.)?" + re.escape(name) + r"\s*\)", text)),
                "synchronizedThis": bool(re.search(r"synchronized\s*\(\s*this\s*\)", text)),
                "cloneOfField": bool(re.search(r"\b" + re.escape(name) + r"\s*\.\s*clone\s*\(", text)),
                "lock": bool(re.search(r"\b(ReentrantLock|\.lock\(\)|StampedLock|Semaphore)\b", text)),
                "threadLocal": "ThreadLocal" in text,
            }
            res.append(dict(f, field=name, uses=use[:40], hints=hints))
    except Exception as e:  # noqa: BLE001
        for f in items:
            res.append(dict(f, error=repr(e)[:200]))
    finally:
        shutil.rmtree(d, ignore_errors=True)

with open(os.path.join(out, "triage_context.jsonl"), "w") as w:
    for r in res:
        w.write(json.dumps(r) + "\n")
print(f"{len(res)} findings in {len(by_repo)} repositories")
