"""Detector unit tests. Run with: python3 -m pytest tests/

These tests do NOT require pytest in production; the launcher uses stdlib only.
But pytest is convenient for development. The tests themselves use only stdlib
unittest under the hood.
"""
import sys
import tempfile
import unittest
from pathlib import Path

# Allow running tests from repo root without pip-installing
HERE = Path(__file__).parent.resolve()
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

from wp_shell_hunter.detectors.disguised_php import DisguisedPhpDetector
from wp_shell_hunter.detectors.doubled_dir import DoubledDirDetector
from wp_shell_hunter.detectors.obfuscation import ObfuscationDetector
from wp_shell_hunter.finding import Severity, Confidence


# Minimal "BiaoJiOk-style" sample (defanged: no eval, no curl_exec).
# Triggers obfuscation detector via goto + quad-md5 + indirect-var patterns.
DEFANGED_SAMPLE = b"""<?php
goto a1Bc2dE3; b3CdEf4G:
md5(md5(md5(md5($_REQUEST[7]))));
goto a1Bc2dE3;
goto z9YxWv8U; goto m5NlOp6Q; goto k4LkJh3R;
goto p7QwEr1A; goto t8YuIo2S;
$arr = explode("\\x2a", $_REQUEST[3]);
[DEFANGED-eval]($GLOBALS[$varname[3+2]]);
"""


class DisguisedPhpTests(unittest.TestCase):
    def setUp(self):
        self.det = DisguisedPhpDetector()
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name: str, content: bytes) -> Path:
        p = self.dir / name
        p.write_bytes(content)
        return p

    def test_php_in_tiff_detected(self):
        p = self._write("evil.tiff", b"<?php echo 1;")
        f = self.det.check(p)
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, Severity.MALICIOUS)
        self.assertEqual(f.confidence, Confidence.HIGH)
        self.assertIn("starts_with_php_open_tag", f.indicators)
        self.assertIn("uncommon_disguise_extension", f.indicators)

    def test_php_in_gif_detected(self):
        p = self._write("evil.gif", b"<?php exit;")
        f = self.det.check(p)
        self.assertIsNotNone(f)

    def test_real_gif_not_flagged(self):
        # Real GIF magic bytes
        p = self._write("real.gif", b"GIF89a\x01\x00\x01\x00")
        f = self.det.check(p)
        self.assertIsNone(f)

    def test_php_file_not_flagged_by_this_detector(self):
        # .php extension is not in the media list — not this detector's job
        p = self._write("ok.php", b"<?php echo 1;")
        f = self.det.check(p)
        self.assertIsNone(f)

    def test_empty_file_not_flagged(self):
        p = self._write("empty.tiff", b"")
        f = self.det.check(p)
        self.assertIsNone(f)


class DoubledDirTests(unittest.TestCase):
    def setUp(self):
        self.det = DoubledDirDetector()

    def test_doubled_maint_flagged(self):
        f = self.det.check(Path("/var/www/site/wp-admin/maint/maint/x.tiff"))
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, Severity.SUSPICIOUS)

    def test_triple_doubling_high_confidence(self):
        f = self.det.check(Path("/home/u/site/images/images/images/x.gif"))
        self.assertIsNotNone(f)
        self.assertEqual(f.confidence, Confidence.HIGH)

    def test_legitimate_simplepie_not_flagged(self):
        f = self.det.check(Path(
            "/var/www/wp-includes/SimplePie/library/SimplePie/HTTP/HTTP/Foo.php"
        ))
        # SimplePie/SimplePie and HTTP/HTTP are PSR-4 patterns and whitelisted
        self.assertIsNone(f)

    def test_normal_path_not_flagged(self):
        f = self.det.check(Path("/var/www/wp-content/themes/twentytwo/style.css"))
        self.assertIsNone(f)


class ObfuscationTests(unittest.TestCase):
    def setUp(self):
        self.det = ObfuscationDetector()
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name: str, content: bytes) -> Path:
        p = self.dir / name
        p.write_bytes(content)
        return p

    def test_defanged_sample_still_detected_via_structural_patterns(self):
        p = self._write("evil.txt", DEFANGED_SAMPLE)
        f = self.det.check(p)
        self.assertIsNotNone(f, "defanged BiaoJiOk-style sample should still hit on structural patterns")
        self.assertGreaterEqual(len(f.indicators), 2)

    def test_clean_php_not_flagged(self):
        p = self._write("ok.php", b"<?php\necho 'hello world';\n")
        f = self.det.check(p)
        self.assertIsNone(f)

    def test_clean_html_not_flagged(self):
        p = self._write("index.html", b"<!doctype html><html><body>hi</body></html>")
        f = self.det.check(p)
        self.assertIsNone(f)

    def test_minified_jquery_not_flagged(self):
        # Synthetic minified JS — no PHP at all, should be quickly rejected
        p = self._write(
            "jquery.min.js",
            b"!function(e,t){\"use strict\";var n=[],r=Object.getPrototypeOf;}(window);"
        )
        f = self.det.check(p)
        self.assertIsNone(f)

    def test_oversized_file_skipped(self):
        # 6 MB of zeros with PHP open at start — should skip due to size cap
        big = b"<?php\n" + b"\x00" * (6 * 1024 * 1024)
        p = self._write("big.php", big)
        f = self.det.check(p)
        self.assertIsNone(f)


if __name__ == "__main__":
    unittest.main()
