#!/usr/bin/env python3
"""pqc-share-scan: find cryptographic engine objects that are shared between threads in Java code,
and inventory the algorithms they use (classical vs post-quantum).

Why: the shared-key study (this repository) shows that ONE JCA Signature object used by several
threads makes Bouncy Castle ML-DSA return corrupted signatures, throw internal errors, and even emit
valid signatures over messages nobody asked to sign (e.g. the empty message). JCA engine objects
(Signature, Cipher, Mac, MessageDigest, KeyAgreement, KEM.Encapsulator/Decapsulator) are not
thread-safe, but they are routinely stored in static fields, singleton services and Spring @Bean
definitions. This scanner finds those places before a PQC migration turns them into incidents.

Usage:
  python3 pqc_share_scan.py <path> [--json out.json] [--sarif out.sarif] [--html out.html]
Exit code: 0 = no HIGH findings, 1 = at least one HIGH finding (usable as a CI gate), 2 = usage error.
Author: Ayman Alsadig Mohamed Suliman. License: MIT.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field

__version__ = "1.0.0"

ENGINE_TYPES = {
    "Signature": "java.security.Signature",
    "Cipher": "javax.crypto.Cipher",
    "Mac": "javax.crypto.Mac",
    "MessageDigest": "java.security.MessageDigest",
    "KeyAgreement": "javax.crypto.KeyAgreement",
    "Encapsulator": "javax.crypto.KEM.Encapsulator",
    "Decapsulator": "javax.crypto.KEM.Decapsulator",
}
SINGLETON_ANNOTATIONS = {
    "Service", "Component", "Controller", "RestController", "Repository", "Configuration",
    "Singleton", "ApplicationScoped", "Stateless", "Startup", "Named",
}

PQC = re.compile(r"^(ML-?DSA|ML-?KEM|SLH-?DSA|DILITHIUM|KYBER|SPHINCS|FALCON|FN-?DSA|HQC|XMSS|LMS|HSS)", re.I)
QUANTUM_VULNERABLE = re.compile(r"(RSA|ECDSA|ECDH|^EC$|^DSA|DH$|^DH|Ed25519|Ed448|X25519|X448|EdDSA|XDH)", re.I)
HASH_OR_SYMMETRIC = re.compile(r"^(SHA|SHA3|HMAC|AES|ChaCha|PBKDF|HKDF|Poly1305|SHAKE)", re.I)


@dataclass
class Finding:
    rule: str
    severity: str           # HIGH / MEDIUM / INFO
    file: str
    line: int
    message: str
    snippet: str
    remediation: str = ""


@dataclass
class AlgorithmUse:
    file: str
    line: int
    api: str
    algorithm: str
    category: str           # post-quantum / quantum-vulnerable / symmetric-or-hash / other


@dataclass
class Report:
    tool: str = f"pqc-share-scan {__version__}"
    root: str = ""
    files_scanned: int = 0
    findings: list = field(default_factory=list)
    algorithms: list = field(default_factory=list)


def strip_comments(src: str) -> str:
    """Blank out comments while keeping line numbers and string literals intact."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == '"' or c == "'":
            q = c
            j = i + 1
            while j < n and src[j] != q:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1]); i = j + 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j])); i = j
        else:
            out.append(c); i += 1
    return "".join(out)


def line_of(src: str, pos: int) -> int:
    return src.count("\n", 0, pos) + 1


def classify(alg: str) -> str:
    base = alg.split("/")[0]
    m = re.search(r"with(.+)$", base, re.I)        # "SHA256withRSA" -> the signature part decides
    if m:
        base = m.group(1)
    if PQC.search(base):
        return "post-quantum"
    if HASH_OR_SYMMETRIC.search(base):
        return "symmetric-or-hash"
    if QUANTUM_VULNERABLE.search(base):
        return "quantum-vulnerable"
    return "other"


TYPE_ALT = "|".join(ENGINE_TYPES)
FIELD_RE = re.compile(
    r"(?P<mods>(?:\b(?:public|protected|private|static|final|volatile|transient)\s+)*)"
    r"(?<![\w.$])(?:(?:java\.security\.|javax\.crypto\.)?(?:KEM\.)?)(?P<type>" + TYPE_ALT + r")\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?P<tail>[=;])")
THREADLOCAL_RE = re.compile(r"ThreadLocal\s*<\s*(?:[\w.]*\.)?(?:" + TYPE_ALT + r")\s*>")
BEAN_RE = re.compile(
    r"@Bean\b(?P<between>[^{;]*?)\b(?:public\s+|protected\s+|private\s+)?(?:static\s+)?"
    r"(?<![\w.$])(?:(?:java\.security\.|javax\.crypto\.)?(?:KEM\.)?)(?P<type>" + TYPE_ALT + r")\s+(?P<name>\w+)\s*\(", re.S)
GETINSTANCE_RE = re.compile(
    r"\b(?P<api>Signature|Cipher|Mac|MessageDigest|KeyAgreement|KEM|KeyPairGenerator|KeyGenerator|KeyFactory)"
    r"\s*\.\s*getInstance\s*\(\s*\"(?P<alg>[^\"]+)\"")
CLASS_RE = re.compile(r"(?P<annos>(?:@\w+(?:\([^)]*\))?\s*)*)(?:public\s+|final\s+|abstract\s+)*class\s+(?P<name>\w+)")


def class_spans(src: str):
    """(start, end, annotations, name) for each top-level-ish class, by brace matching."""
    spans = []
    for m in CLASS_RE.finditer(src):
        brace = src.find("{", m.end())
        if brace < 0:
            continue
        depth, j = 0, brace
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        annos = set(re.findall(r"@(\w+)", m.group("annos")))
        spans.append((brace, j, annos, m.group("name")))
    return spans


def depth_at(src: str, pos: int, start: int) -> int:
    seg = src[start:pos]
    return seg.count("{") - seg.count("}")


def enclosing_class(spans, pos):
    best = None
    for s in spans:
        if s[0] < pos < s[1] and (best is None or s[0] > best[0]):
            best = s
    return best


QUICK_RE = re.compile(r"\b(?:java\.security|javax\.crypto)\b")
IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+?)(\.\*)?\s*;", re.M)
JCA_HOME = {"Signature": "java.security", "MessageDigest": "java.security", "Cipher": "javax.crypto", "Mac": "javax.crypto",
            "KeyAgreement": "javax.crypto", "Encapsulator": "javax.crypto.KEM", "Decapsulator": "javax.crypto.KEM"}


def jca_types_in_scope(src: str) -> set:
    """Simple type names that resolve to the JCA class in this file. Other libraries reuse these names
    (cglib/ASM Signature, Apple-style Mac, ...), so a bare name counts only when an import points to the JCA."""
    explicit, wild = {}, set()
    for m in IMPORT_RE.finditer(src):
        name, star = m.group(1), m.group(2)
        if star:
            wild.add(name)
        else:
            explicit[name.rsplit(".", 1)[-1]] = name.rsplit(".", 1)[0]
    pkg = re.search(r"^\s*package\s+([\w.]+)\s*;", src, re.M)
    pkg = pkg.group(1) if pkg else ""
    ok = set()
    for t, home in JCA_HOME.items():
        if t in explicit:
            if explicit[t] in (home, "javax.crypto.KEM") or explicit[t].endswith("KEM") and t in ("Encapsulator", "Decapsulator"):
                ok.add(t)
        elif home in wild or (t in ("Encapsulator", "Decapsulator") and "javax.crypto" in explicit.get("KEM", "") ):
            ok.add(t)
        elif pkg == home:
            ok.add(t)
    return ok


def scan_java(path: str, rel: str, report: Report) -> None:
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    if not QUICK_RE.search(raw):        # fast path: most files touch no JCA engine type at all
        return
    src = strip_comments(raw)
    lines = raw.splitlines()
    spans = class_spans(src)
    in_scope = jca_types_in_scope(src)
    is_jca = lambda m: m.group(0).lstrip().startswith(("java.", "javax.")) or "java.security." in m.group(0) \
        or "javax.crypto." in m.group(0) or m.group("type") in in_scope
    snippet = lambda ln: lines[ln - 1].strip()[:160] if 0 < ln <= len(lines) else ""

    tl_lines = {line_of(src, m.start()) for m in THREADLOCAL_RE.finditer(src)}
    for ln in sorted(tl_lines):
        report.findings.append(Finding(
            "PQS000-threadlocal-engine", "INFO", rel, ln,
            "Engine object kept per thread in a ThreadLocal: the recommended pattern.", snippet(ln)))

    for m in FIELD_RE.finditer(src):
        ln = line_of(src, m.start())
        if ln in tl_lines or not is_jca(m):
            continue
        cls = enclosing_class(spans, m.start())
        if cls is None or depth_at(src, m.start(), cls[0]) != 1:
            continue                                    # local variable or nested block, not a field
        mods = m.group("mods") or ""
        t = m.group("type")
        singleton = bool(cls[2] & SINGLETON_ANNOTATIONS)
        if "static" in mods:
            sev, why = "HIGH", "a static field: one object for the whole JVM, shared by every thread"
        elif singleton:
            sev, why = "HIGH", f"a field of a singleton (@{', @'.join(sorted(cls[2] & SINGLETON_ANNOTATIONS))}): shared by every request thread"
        else:
            sev, why = "MEDIUM", "an instance field: shared if this object is used from several threads"
        report.findings.append(Finding(
            "PQS001-shared-engine-field", sev, rel, ln,
            f"{ENGINE_TYPES[t]} '{m.group('name')}' held in {why}. JCA engine objects are not "
            f"thread-safe; concurrent use corrupts their state.",
            snippet(ln),
            f"Create the {t} per operation (getInstance is cheap next to ML-DSA signing), keep it in a "
            f"ThreadLocal, or guard every init/update/final sequence with one lock."))

    for m in BEAN_RE.finditer(src):
        if re.search(r"@Scope\s*\(\s*(?:value\s*=\s*)?(?:\"prototype\"|ConfigurableBeanFactory\.SCOPE_PROTOTYPE)", m.group("between")):
            continue
        if not is_jca(m):
            continue
        ln = line_of(src, m.start("type"))
        t = m.group("type")
        report.findings.append(Finding(
            "PQS002-singleton-engine-bean", "HIGH", rel, ln,
            f"Spring @Bean '{m.group('name')}' returns a {ENGINE_TYPES[t]}; beans are singletons by "
            f"default, so every injecting component shares ONE engine object across threads.",
            snippet(ln),
            "Inject a factory (e.g. a Supplier<Signature> or a KeyPair/PrivateKey bean) and create the "
            "engine per call, or declare the bean @Scope(\"prototype\") AND inject it per use."))

    for m in GETINSTANCE_RE.finditer(src):
        ln = line_of(src, m.start())
        alg = m.group("alg")
        report.algorithms.append(AlgorithmUse(rel, ln, m.group("api"), alg, classify(alg)))


def scan(root: str) -> Report:
    report = Report(root=os.path.abspath(root))
    paths = [root] if os.path.isfile(root) else [
        os.path.join(d, f) for d, _, fs in os.walk(root)
        for f in fs if f.endswith(".java") and not any(p in d for p in (os.sep + ".git", os.sep + "build", os.sep + "target"))]
    for p in sorted(paths):
        rel = os.path.relpath(p, root if os.path.isdir(root) else os.path.dirname(root))
        scan_java(p, rel, report)
        report.files_scanned += 1
    order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
    report.findings.sort(key=lambda f: (order[f.severity], f.file, f.line))
    return report


def to_sarif(report: Report) -> dict:
    level = {"HIGH": "error", "MEDIUM": "warning", "INFO": "note"}
    rules = sorted({f.rule for f in report.findings})
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "pqc-share-scan", "version": __version__,
                                "rules": [{"id": r, "shortDescription": {"text": r}} for r in rules]}},
            "results": [{
                "ruleId": f.rule, "level": level[f.severity],
                "message": {"text": f.message + (" Fix: " + f.remediation if f.remediation else "")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file.replace(os.sep, "/")},
                                                    "region": {"startLine": f.line}}}],
            } for f in report.findings],
        }],
    }


def to_html(report: Report) -> str:
    e = html.escape
    counts = {s: sum(f.severity == s for f in report.findings) for s in ("HIGH", "MEDIUM", "INFO")}
    cats = {}
    for a in report.algorithms:
        cats[a.category] = cats.get(a.category, 0) + 1
    rows = "".join(
        f"<tr class='{f.severity.lower()}'><td><span class='sev'>{f.severity}</span></td><td><code>{e(f.file)}:{f.line}</code></td>"
        f"<td>{e(f.message)}<div class='snip'><code>{e(f.snippet)}</code></div>"
        f"{'<div class=fix><b>Fix:</b> ' + e(f.remediation) + '</div>' if f.remediation else ''}</td></tr>"
        for f in report.findings) or "<tr><td colspan=3>No findings.</td></tr>"
    arows = "".join(
        f"<tr><td><code>{e(a.file)}:{a.line}</code></td><td>{e(a.api)}</td><td><code>{e(a.algorithm)}</code></td>"
        f"<td><span class='cat {a.category}'>{a.category}</span></td></tr>" for a in report.algorithms) \
        or "<tr><td colspan=4>No getInstance calls found.</td></tr>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>pqc-share-scan report</title>
<style>
:root{{--bg:#fff;--fg:#14202b;--muted:#5b6b78;--line:#e3e8ec;--high:#b42318;--med:#b54708;--info:#175cd3;--pq:#067647;--qv:#b42318}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1720;--fg:#e6edf3;--muted:#9fb0bf;--line:#243241}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:24px 16px}}h1{{margin:0 0 4px}}p.m{{color:var(--muted);margin:0 0 20px}}
.k{{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 24px}}.k div{{border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:120px}}
.k b{{display:block;font-size:24px}}table{{width:100%;border-collapse:collapse;margin:0 0 28px}}
td,th{{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}
.sev{{font-weight:700}}.high .sev{{color:var(--high)}}.medium .sev{{color:var(--med)}}.info .sev{{color:var(--info)}}
.snip{{color:var(--muted);margin-top:4px;overflow-x:auto}}.fix{{margin-top:4px}}.cat{{font-weight:600}}
.post-quantum{{color:var(--pq)}}.quantum-vulnerable{{color:var(--qv)}}code{{font-size:13px}}
</style></head><body><main>
<h1>pqc-share-scan report</h1><p class="m">{e(report.tool)} · {report.files_scanned} Java files · {e(report.root)}</p>
<div class="k"><div><b>{counts['HIGH']}</b>HIGH</div><div><b>{counts['MEDIUM']}</b>MEDIUM</div><div><b>{counts['INFO']}</b>INFO (safe pattern)</div>
<div><b>{cats.get('quantum-vulnerable', 0)}</b>quantum-vulnerable uses</div><div><b>{cats.get('post-quantum', 0)}</b>post-quantum uses</div></div>
<h2>Shared crypto engine objects</h2><table><tr><th>Severity</th><th>Location</th><th>Finding</th></tr>{rows}</table>
<h2>Cryptographic algorithm inventory</h2><table><tr><th>Location</th><th>API</th><th>Algorithm</th><th>Category</th></tr>{arows}</table>
</main></body></html>"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Find thread-shared JCA engine objects and inventory algorithms.")
    ap.add_argument("path")
    ap.add_argument("--json"); ap.add_argument("--sarif"); ap.add_argument("--html")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    if not os.path.exists(a.path):
        print(f"no such path: {a.path}", file=sys.stderr)
        return 2
    rep = scan(a.path)
    data = {"tool": rep.tool, "root": rep.root, "files_scanned": rep.files_scanned,
            "findings": [asdict(f) for f in rep.findings], "algorithms": [asdict(x) for x in rep.algorithms]}
    if a.json:
        json.dump(data, open(a.json, "w"), indent=2)
    if a.sarif:
        json.dump(to_sarif(rep), open(a.sarif, "w"), indent=2)
    if a.html:
        open(a.html, "w").write(to_html(rep))
    for f in rep.findings:
        print(f"{f.severity:6} {f.file}:{f.line}  {f.rule}  {f.message}")
    cats = {}
    for x in rep.algorithms:
        cats[x.category] = cats.get(x.category, 0) + 1
    print(f"\n{rep.files_scanned} files, {sum(f.severity == 'HIGH' for f in rep.findings)} HIGH, "
          f"{sum(f.severity == 'MEDIUM' for f in rep.findings)} MEDIUM; algorithms: {cats}")
    return 1 if any(f.severity == "HIGH" for f in rep.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
