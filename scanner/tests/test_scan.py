"""Unit tests for pqc-share-scan (python3 -m unittest discover scanner/tests)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import pqc_share_scan as s  # noqa: E402

CORPUS = os.path.join(HERE, "corpus")


class ScanCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = s.scan(CORPUS)
        cls.by = {}
        for f in cls.r.findings:
            cls.by.setdefault((os.path.basename(f.file), f.rule, f.severity), []).append(f)

    def count(self, file, rule, sev):
        return len(self.by.get((file, rule, sev), []))

    def test_singleton_service_fields_are_high(self):
        self.assertEqual(self.count("PaymentSigningService.java", "PQS001-shared-engine-field", "HIGH"), 2)

    def test_static_field_is_high_and_comments_ignored(self):
        self.assertEqual(self.count("LegacyUtil.java", "PQS001-shared-engine-field", "HIGH"), 1)

    def test_plain_instance_field_is_medium(self):
        self.assertEqual(self.count("LegacyUtil.java", "PQS001-shared-engine-field", "MEDIUM"), 1)

    def test_singleton_bean_high_prototype_skipped(self):
        self.assertEqual(self.count("CryptoConfig.java", "PQS002-singleton-engine-bean", "HIGH"), 1)
        names = [f.message for f in self.r.findings if f.file.endswith("CryptoConfig.java")]
        self.assertFalse(any("hmac" in m for m in names))

    def test_threadlocal_is_info_not_high(self):
        self.assertEqual(self.count("SafeSigner.java", "PQS000-threadlocal-engine", "INFO"), 1)
        self.assertEqual(sum(1 for f in self.r.findings if f.file.endswith("SafeSigner.java") and f.severity != "INFO"), 0)

    def test_no_local_variables_reported(self):
        self.assertFalse(any("'local'" in f.message or "'s'" in f.message for f in self.r.findings))

    def test_total_high(self):
        self.assertEqual(sum(f.severity == "HIGH" for f in self.r.findings), 4)

    def test_inventory_categories(self):
        cats = {(a.algorithm, a.category) for a in self.r.algorithms}
        for pair in [("ML-DSA", "post-quantum"), ("ML-DSA-65", "post-quantum"), ("ML-KEM-768", "post-quantum"),
                     ("SHA256withRSA", "quantum-vulnerable"), ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "quantum-vulnerable"),
                     ("ECDH", "quantum-vulnerable"), ("HmacSHA256", "symmetric-or-hash"), ("SHA-256", "symmetric-or-hash")]:
            self.assertIn(pair, cats)


class Lookalikes(unittest.TestCase):
    def test_types_that_only_end_with_an_engine_name_are_ignored(self):
        src = ("@Service class B { private PDSignature pdSignature; private static XMac xmac; "
               "private java.security.Signature real; }")
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "B.java"), "w").write(src)
            names = [f.message for f in s.scan(d).findings]
        self.assertEqual(len(names), 1)
        self.assertIn("'real'", names[0])


class ImportResolution(unittest.TestCase):
    def scan_src(self, src):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "C.java"), "w").write(src)
            return s.scan(d).findings

    def test_non_jca_signature_type_is_ignored(self):      # cglib / ASM have their own Signature class
        self.assertEqual(self.scan_src("import org.springframework.cglib.core.Signature;\n"
                                       "class C { private static final Signature COPY = null; }"), [])

    def test_bare_name_without_import_is_ignored(self):
        self.assertEqual(self.scan_src("package x; class C { private static Signature s; }"), [])

    def test_wildcard_import_counts(self):
        self.assertEqual(len(self.scan_src("import java.security.*;\nclass C { private static Signature s; }")), 1)


class Cli(unittest.TestCase):
    def test_outputs_and_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            j, sa, h = (os.path.join(d, x) for x in ("o.json", "o.sarif", "o.html"))
            p = subprocess.run([sys.executable, os.path.join(os.path.dirname(HERE), "pqc_share_scan.py"), CORPUS,
                                "--json", j, "--sarif", sa, "--html", h], capture_output=True, text=True)
            self.assertEqual(p.returncode, 1)               # HIGH findings -> CI gate fails
            sarif = json.load(open(sa))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), len(json.load(open(j))["findings"]))
            self.assertIn("pqc-share-scan report", open(h).read())

    def test_clean_tree_exits_zero(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "A.java"), "w").write("class A { void f() throws Exception { java.security.Signature s = java.security.Signature.getInstance(\"ML-DSA\"); } }")
            p = subprocess.run([sys.executable, os.path.join(os.path.dirname(HERE), "pqc_share_scan.py"), d], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout)


if __name__ == "__main__":
    unittest.main()
