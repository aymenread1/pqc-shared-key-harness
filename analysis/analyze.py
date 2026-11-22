#!/usr/bin/env python3
"""Turn RESULT lines from harness runs into tables and figures for the paper.

Input: any text containing RESULT lines (CI job summary, run-all details.txt, logs).
Output (in --out): misuse.csv, misuse_summary.csv, misuse_summary.md, fig_outcomes.png, fig_sweep.png
Rates carry Wilson 95% confidence intervals, pooled over repeated runs of the same configuration.
"""
import argparse
import csv
import math
import os
import re
from collections import defaultdict

KEYS = ["ok", "loud", "invalid", "crossValid", "mixedValid", "emptyMessage", "total"]


def parse(text):
    rows = []
    for line in text.splitlines():
        i = line.find("RESULT ")
        if i < 0 or "mode=" not in line:
            continue
        kv = dict(re.findall(r"(\w+)=([^\s()]+)", line[i:]))
        m = re.search(r"of which emptyMessage=(\d+)", line)          # older line format
        if m:
            kv["emptyMessage"] = m.group(1)
        prov = kv.get("provider", "BC/1.81" if "provider" not in kv else kv["provider"])
        try:
            r = {k: int(kv.get(k, 0)) for k in KEYS}
        except ValueError:
            continue
        r.update(provider=prov, alg=kv.get("alg", "?"), mode=kv.get("mode", "?"),
                 threads=int(kv.get("threads", 0)), msgBytes=int(kv.get("msgBytes", 0)), java=kv.get("java", ""))
        rows.append(r)
    return rows


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (p, max(0.0, c - h), min(1.0, c + h))


def summarise(rows):
    g = defaultdict(lambda: defaultdict(int))
    runs = defaultdict(int)
    for r in rows:
        key = (r["provider"], r["alg"], r["mode"], r["threads"], r["msgBytes"])
        runs[key] += 1
        for k in KEYS:
            g[key][k] += r[k]
    out = []
    for key, s in sorted(g.items()):
        n = s["total"]
        silent = s["invalid"] + s["crossValid"] + s["mixedValid"]
        rec = dict(zip(["provider", "alg", "mode", "threads", "msgBytes"], key), runs=runs[key], total=n)
        for name, k in [("ok", s["ok"]), ("loud", s["loud"]), ("silentWrong", silent), ("unrequestedValid", s["mixedValid"]),
                        ("emptyMessage", s["emptyMessage"]), ("crossValid", s["crossValid"])]:
            p, lo, hi = wilson(k, n)
            rec[name] = k
            rec[name + "_pct"] = round(100 * p, 3)
            rec[name + "_ci"] = f"{100 * lo:.2f}-{100 * hi:.2f}"
        out.append(rec)
    return out


def write_tables(summary, rows, outdir):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "misuse.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    with open(os.path.join(outdir, "misuse_summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        w.writeheader(); w.writerows(summary)
    with open(os.path.join(outdir, "misuse_summary.md"), "w") as f:
        f.write("| Provider | Mode | Threads | Msg bytes | Runs | Ops | Correct % | Exception % | Silent wrong % (95% CI) | Unrequested-message valid % (95% CI) | of which empty |\n")
        f.write("|---|---|---|---|---|---|---|---|---|---|---|\n")
        for s in summary:
            f.write(f"| {s['provider']} | {s['mode']} | {s['threads']} | {s['msgBytes']} | {s['runs']} | {s['total']} | "
                    f"{s['ok_pct']:.2f} | {s['loud_pct']:.2f} | {s['silentWrong_pct']:.2f} ({s['silentWrong_ci']}) | "
                    f"{s['unrequestedValid_pct']:.2f} ({s['unrequestedValid_ci']}) | {s['emptyMessage']} |\n")


def figures(summary, outdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed: tables only")
        return
    cols = {"ok": "#2E7D32", "loud": "#F9A825", "silentWrong": "#C62828", "unrequestedValid": "#6A1B9A"}
    labels = {"ok": "correct", "loud": "exception (fail-loud)", "silentWrong": "silent wrong output",
              "unrequestedValid": "valid on unrequested message"}
    shared = [s for s in summary if s["mode"] == "shared"]
    if shared:
        names = [f"{s['provider'].split('/')[0]}\n{s['threads']}t · {s['msgBytes']} B" for s in shared]
        fig, ax = plt.subplots(figsize=(max(6, 0.9 * len(shared)), 4))
        bottom = [0.0] * len(shared)
        for k in ["ok", "loud", "silentWrong"]:
            vals = [s[k + "_pct"] for s in shared]
            ax.bar(names, vals, bottom=bottom, color=cols[k], label=labels[k])
            bottom = [b + v for b, v in zip(bottom, vals)]
        ax.set_ylabel("% of signing operations")
        ax.set_title("One Signature object shared without a lock: outcome mix")
        ax.legend(frameon=False, fontsize=8, loc="lower right")
        ax.spines[["top", "right"]].set_visible(False)
        plt.xticks(fontsize=7)
        fig.tight_layout(); fig.savefig(os.path.join(outdir, "fig_outcomes.png"), dpi=200); plt.close(fig)

    provs = sorted({s["provider"] for s in shared})
    sizes = sorted({s["msgBytes"] for s in shared})
    if shared and len({s["threads"] for s in shared}) > 1:
        fig, axes = plt.subplots(1, len(provs), figsize=(5 * len(provs), 3.6), squeeze=False)
        for ax, pv in zip(axes[0], provs):
            for sz in sizes:
                pts = sorted((s["threads"], 100 - s["ok_pct"]) for s in shared if s["provider"] == pv and s["msgBytes"] == sz)
                if len(pts) > 1:
                    ax.plot([p[0] for p in pts], [p[1] for p in pts], marker="o", label=f"{sz} B")
            ax.set_xscale("log", base=2); ax.set_xlabel("threads sharing the object")
            ax.set_ylabel("% operations not correct"); ax.set_title(pv, fontsize=10)
            ax.spines[["top", "right"]].set_visible(False); ax.legend(frameon=False, fontsize=8)
        fig.tight_layout(); fig.savefig(os.path.join(outdir, "fig_sweep.png"), dpi=200); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--out", default="analysis/out")
    a = ap.parse_args()
    rows = []
    for p in a.inputs:
        rows += parse(open(p, encoding="utf-8").read())
    if not rows:
        raise SystemExit("no RESULT lines found")
    summary = summarise(rows)
    write_tables(summary, rows, a.out)
    figures(summary, a.out)
    print(open(os.path.join(a.out, "misuse_summary.md")).read())


if __name__ == "__main__":
    main()
