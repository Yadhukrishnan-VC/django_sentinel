"""Regression tests for bugs found in the code review."""
import tempfile
import unittest
from pathlib import Path

from djangosentinel.analysis.confidence import deduplicate
from djangosentinel.fixers.ast_safe_fixer import ASTSafeFixer
from djangosentinel.models import (
    CodeLocation, Fix, Severity, VulnCategory, Vulnerability,
)
from djangosentinel.scanners.dependency_scanner import DependencyScanner
from djangosentinel.scanners.django_scanner import DjangoScanner


def _vuln(line, source="", file="app/views.py", cwe="CWE-94", title="Use of eval()"):
    return Vulnerability(
        vuln_id=f"v{line}{source}", title=title, category=VulnCategory.INJECTION,
        severity=Severity.HIGH, location=CodeLocation(file, line, snippet="eval(x)"),
        description="d", cwe_id=cwe, metadata={"source": source, "confidence": 0.7},
    )


class TestDeduplicate(unittest.TestCase):
    def test_same_scanner_neighbouring_lines_are_kept(self):
        found = deduplicate([_vuln(4), _vuln(5), _vuln(6)])
        self.assertEqual(sorted(v.location.line_number for v in found), [4, 5, 6])

    def test_different_scanners_same_or_adjacent_line_are_merged(self):
        found = deduplicate([_vuln(10, "ast_scanner"), _vuln(11, "taint_tracker")])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].metadata["duplicate_count"], 1)

    def test_same_line_is_merged(self):
        self.assertEqual(len(deduplicate([_vuln(7, "a"), _vuln(7, "b")])), 1)

    def test_far_apart_findings_are_kept(self):
        self.assertEqual(len(deduplicate([_vuln(3, "a"), _vuln(9, "b")])), 2)

    def test_different_files_or_cwe_are_kept(self):
        found = deduplicate([_vuln(3, "a"), _vuln(3, "b", file="other.py"), _vuln(3, "c", cwe="CWE-78")])
        self.assertEqual(len(found), 3)

    def test_order_is_stable(self):
        items = [_vuln(30, "a"), _vuln(5, "a", file="b.py"), _vuln(1, "a", file="c.py")]
        self.assertEqual([v.location.line_number for v in deduplicate(items)], [30, 5, 1])


class TestFixerKeepsFilesIntact(unittest.TestCase):
    def _fix(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, data in files.items():
                (root / name).write_bytes(data)
            vulns = DjangoScanner(str(root)).scan()
            fixer = ASTSafeFixer(str(root), backup=False)
            fixer.apply_all(vulns)
            return {name: (root / name).read_bytes() for name in files}

    def test_crlf_line_endings_are_preserved(self):
        out = self._fix({"settings.py": b"DEBUG = True\r\nNAME = 'x'\r\n"})
        data = out["settings.py"]
        self.assertIn(b"DEBUG = False", data)
        self.assertNotIn(b"\n", data.replace(b"\r\n", b""))

    def test_lf_line_endings_are_preserved(self):
        out = self._fix({"settings.py": b"DEBUG = True\nNAME = 'x'\n"})
        self.assertNotIn(b"\r", out["settings.py"])

    def test_non_utf8_file_is_not_modified(self):
        original = "# caf\u00e9\nDEBUG = True\n".encode("latin-1")
        out = self._fix({"legacy.py": original})
        self.assertEqual(out["legacy.py"], original)


class TestDangerousImportScan(unittest.TestCase):
    def _scan(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "m.py").write_text(source, encoding="utf-8")
            return [v.title for v in DependencyScanner(tmp).scan()]

    def test_detects_pickle_import(self):
        self.assertTrue(any("pickle" in t for t in self._scan("import pickle\n")))

    def test_detects_from_import(self):
        self.assertTrue(any("pickle" in t for t in self._scan("from pickle import loads\n")))

    def test_no_false_positive_on_similar_names(self):
        self.assertFalse(any("Dangerous Module" in t for t in self._scan("import pickled_cache\nx = 1\n")))


if __name__ == "__main__":
    unittest.main()
