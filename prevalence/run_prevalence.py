#!/usr/bin/env python3
"""Prevalence study: run pqc-share-scan over a list of public GitHub repositories.

Input : a text file with one "owner/name sizeKB stars frame" per line.
Output: <out>/repos.jsonl (one record per repository) and <out>/findings.jsonl (one record per finding),
        each finding tagged with the commit scanned so it can be re-checked later.
Each repository is shallow-cloned, scanned and deleted, so disk use stays bounded.
Author: Ayman Alsadig Mohamed Suliman. License: MIT.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scanner"))
import pqc_share_scan as s  # noqa: E402

ENGINE_CALL = re.compile(r"\b(Signature|Cipher|Mac|MessageDigest|KeyAgreement|KEM)\s*\.\s*getInstance\s*\(")
TEST_MARKERS = ("/test/", "/tests/", "/testing/", "/it/", "/jmh/", "/benchmark", "/example", "/sample", "/demo/")


def is_test(path):
    p = "/" + path.replace(os.sep, "/").lower()
    return any(m in p for m in TEST_MARKERS) or p.endswith("test.java") or p.endswith("tests.java")


def one(line, workdir, max_kb):
    name, size, stars, frame = (line.split() + ["", "", "", ""])[:4]
    rec = {"repo": name, "sizeKB": int(size or 0), "stars": int(stars or 0), "frame": frame}
    if rec["sizeKB"] > max_kb:
        rec["status"] = "skipped-size"
        return rec, []
    d = tempfile.mkdtemp(dir=workdir)
    t0 = time.time()
    try:
        r = subprocess.run(["git", "clone", "-q", "--depth", "1", f"https://github.com/{name}", d],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            rec["status"] = "clone-failed"
            rec["error"] = r.stderr.strip()[-200:]
            return rec, []
        rec["commit"] = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        rep = s.scan(d)
        rec["status"] = "ok"
        rec["javaFiles"] = rep.files_scanned
        calls = 0
        for root, _, files in os.walk(d):
            if "/.git" in root:
                continue
            for fn in files:
                if fn.endswith(".java"):
                    try:
                        calls += len(ENGINE_CALL.findall(open(os.path.join(root, fn), encoding="utf-8", errors="replace").read()))
                    except OSError:
                        pass
        rec["engineCalls"] = calls          # every Signature/Cipher/Mac/... getInstance call, literal or not
        cats = {}
        for a in rep.algorithms:
            cats[a.category] = cats.get(a.category, 0) + 1
        rec["algorithmCategories"] = cats
        rec["pqcUses"] = sorted({a.algorithm for a in rep.algorithms if a.category == "post-quantum"})
        fs = []
        for f in rep.findings:
            x = asdict(f)
            x.update(repo=name, commit=rec["commit"], test=is_test(f.file), frame=frame)
            fs.append(x)
        main = [f for f in fs if not f["test"]]
        rec["high"] = sum(f["severity"] == "HIGH" for f in main)
        rec["medium"] = sum(f["severity"] == "MEDIUM" for f in main)
        rec["info"] = sum(f["severity"] == "INFO" for f in main)
        rec["highTest"] = sum(f["severity"] == "HIGH" for f in fs if f["test"])
        return rec, fs
    except subprocess.TimeoutExpired:
        rec["status"] = "clone-timeout"
        return rec, []
    except Exception as e:  # keep going: one odd repository must not stop the study
        rec["status"] = "error"
        rec["error"] = repr(e)[:200]
        return rec, []
    finally:
        rec["seconds"] = round(time.time() - t0, 1)
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("list")
    ap.add_argument("--out", default="prevalence/out")
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--max-kb", type=int, default=600_000)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    done = set()
    rp = os.path.join(a.out, "repos.jsonl")
    if os.path.exists(rp):
        done = {json.loads(l)["repo"] for l in open(rp)}
    lines = [l.strip() for l in open(a.list) if l.strip() and not l.startswith("#")]
    lines = [l for l in lines if l.split()[0] not in done]
    work = tempfile.mkdtemp(prefix="prev-")
    with ThreadPoolExecutor(a.jobs) as ex, open(rp, "a") as R, open(os.path.join(a.out, "findings.jsonl"), "a") as F:
        futs = [ex.submit(one, l, work, a.max_kb) for l in lines]
        for i, fu in enumerate(as_completed(futs), 1):
            rec, fs = fu.result()
            R.write(json.dumps(rec) + "\n"); R.flush()
            for f in fs:
                F.write(json.dumps(f) + "\n")
            F.flush()
            print(f"[{i}/{len(lines)}] {rec['repo']}: {rec['status']} high={rec.get('high', '-')} t={rec.get('seconds', 0)}s", flush=True)
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
