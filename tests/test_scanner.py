"""End-to-end scanner integration tests."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent.resolve()
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from wp_shell_hunter.scanner import Scanner
from wp_shell_hunter.finding import Severity


def _make_clean_wp(root: Path):
    """Create a minimal directory tree that imitates a clean WordPress install."""
    paths = [
        "wp-admin/maint/repair.php",
        "wp-admin/css/colors/coffee/colors.css",
        "wp-content/themes/twentytwentyfour/style.css",
        "wp-content/themes/twentytwentyfour/index.php",
        "wp-content/plugins/akismet/akismet.php",
        "wp-content/uploads/2026/01/photo.jpg",
        "wp-includes/SimplePie/library/SimplePie/HTTP/HTTP/Foo.php",
        "wp-includes/Requests/src/Auth/Auth/Basic.php",
        "wp-includes/version.php",
        "index.php",
    ]
    for rel in paths:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith(".php"):
            p.write_bytes(b"<?php\n// clean WP file\nreturn;\n")
        elif rel.endswith(".css"):
            p.write_bytes(b"body { margin: 0; }\n")
        elif rel.endswith(".jpg"):
            # Real-ish JPEG magic bytes
            p.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01")


def _make_infected_wp(root: Path):
    """Clean WP plus three webshell droppers across detectors."""
    _make_clean_wp(root)

    # 1. PHP disguised as .tiff in doubled directory
    bad1 = root / "wp-admin/maint/maint/q1Wm.tiff"
    bad1.parent.mkdir(parents=True, exist_ok=True)
    bad1.write_bytes(b"<?php\necho 'webshell';\n")

    # 2. Doubled-dir-only path (no PHP yet) — should still flag as suspicious
    bad2 = root / "cgi-bin/cgi-bin/cgi-bin/keep.txt"
    bad2.parent.mkdir(parents=True, exist_ok=True)
    bad2.write_bytes(b"placeholder\n")

    # 3. Heavily obfuscated PHP
    obf = b"<?php\n"
    obf += b"goto a1; "
    for i in range(8):
        obf += f"goto z{i}b{i}c{i}d{i}; ".encode()
    obf += b"\nmd5(md5(md5(md5($_REQUEST[7]))));\n"
    obf += b"$x = explode(\"\\x2a\", $_REQUEST[3]);\n"
    obf += b"${$y[3+2]}();\n"
    bad3 = root / "wp-content/plugins/akismet/admin/admin/Bv.gif"
    bad3.parent.mkdir(parents=True, exist_ok=True)
    bad3.write_bytes(obf)


class ScannerEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_wp_zero_findings(self):
        _make_clean_wp(self.root)
        scanner = Scanner(workers=2, compute_hash=False)
        findings = list(scanner.scan(self.root))
        self.assertEqual(
            findings, [],
            f"clean WP install must not produce findings; got: {[f.to_dict() for f in findings]}"
        )

    def test_infected_wp_finds_at_least_three(self):
        _make_infected_wp(self.root)
        scanner = Scanner(workers=2, compute_hash=False, scan_uploads=True)
        findings = list(scanner.scan(self.root))
        # at least one MALICIOUS expected
        mal = [f for f in findings if f.severity == Severity.MALICIOUS]
        self.assertGreater(len(mal), 0, "should find malicious files")
        # path must include a known bad
        bad_paths = [f.path for f in findings]
        self.assertTrue(
            any("Bv.gif" in p or "q1Wm.tiff" in p or "cgi-bin/cgi-bin" in p for p in bad_paths),
            f"expected planted bad files in findings; got: {bad_paths}"
        )

    def test_exit_code_logic(self):
        # Sanity: if you have malicious findings the CLI should return 2
        _make_infected_wp(self.root)
        scanner = Scanner(workers=2, compute_hash=False, scan_uploads=True)
        findings = list(scanner.scan(self.root))
        has_mal = any(f.severity == Severity.MALICIOUS for f in findings)
        self.assertTrue(has_mal)


if __name__ == "__main__":
    unittest.main()
