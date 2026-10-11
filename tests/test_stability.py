"""
Regression tests for stability fixes:
  * project-relative exclusions (a project under env/ is still scanned, backups are ignored)
  * CLI rejects a missing / non-directory scan path (exit status 2)
  * unparsable files are reported, not silently skipped
  * fixes are applied only when verifiable; template-only fixes go to manual review
  * package exports resolve; AI provider selection; Gemini request format
  * CLI survives a console that cannot encode emoji
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def run_cli(*args, env_extra=None, cwd=None):
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    env.update(env_extra or {})
    proc = subprocess.run(
        [sys.executable, "-m", "djangosentinel", *args],
        capture_output=True, env=env, cwd=cwd,
    )
    # decode leniently: the point of some tests is a non-UTF-8 console
    proc.stdout = proc.stdout.decode("utf-8", errors="replace")
    proc.stderr = proc.stderr.decode("utf-8", errors="replace")
    return proc


class TempDir(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p


class TestExclusions(TempDir):
    def test_is_excluded_uses_project_relative_path(self):
        from djangosentinel.paths import is_excluded
        root = self.root / "env" / "proj"          # project itself lives under "env"
        self.assertFalse(is_excluded(root / "app" / "views.py", root))
        self.assertTrue(is_excluded(root / "venv" / "lib" / "x.py", root))
        self.assertTrue(is_excluded(root / ".sentinel_backups" / "20260101" / "views.py", root))
        self.assertTrue(is_excluded(root / "app" / "migrations" / "0001.py", root))

    def test_project_inside_env_folder_is_still_scanned(self):
        from djangosentinel.scanners import DjangoScanner
        proj = self.root / "env" / "proj"
        proj.mkdir(parents=True)
        (proj / "views.py").write_text("def f(r):\n    eval(r.GET['x'])\n", encoding="utf-8")
        self.assertTrue(DjangoScanner(str(proj)).scan())

    def test_backup_folder_is_not_rescanned(self):
        from djangosentinel.scanners import DjangoScanner
        self.write("settings.py", "DEBUG = False\n")
        self.write(".sentinel_backups/20260101/settings.py", "DEBUG = True\n")
        found = DjangoScanner(str(self.root)).scan()
        self.assertFalse([v for v in found if ".sentinel_backups" in v.location.file_path])


class TestCliGuards(TempDir):
    def test_missing_path_exits_2(self):
        r = run_cli("scan", str(self.root / "does-not-exist"), "--no-color")
        self.assertEqual(r.returncode, 2)
        self.assertIn("Path not found", r.stderr)

    def test_file_instead_of_directory_exits_2(self):
        f = self.write("a.py", "x = 1\n")
        r = run_cli("scan", str(f), "--no-color")
        self.assertEqual(r.returncode, 2)
        self.assertIn("Not a directory", r.stderr)

    def test_legacy_console_encoding_does_not_crash(self):
        self.write("a.py", "x = 1\n")
        r = run_cli("scan", str(self.root), env_extra={"PYTHONIOENCODING": "cp1252"})
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        self.assertNotIn("UnicodeEncodeError", r.stderr)

    def test_syntax_error_file_is_reported(self):
        self.write("ok.py", "x = 1\n")
        self.write("broken.py", "def x(:\n  pass\n")
        r = run_cli("scan", str(self.root), "--format", "json", "--no-color")
        data = json.loads(r.stdout)
        self.assertTrue(any("broken.py" in e for e in data["errors"]), data["errors"])


class TestFixSafety(TempDir):
    VIEWS = (
        "import random\n"
        "def reset_token(request):\n"
        "    token = random.randint(100000, 999999)\n"
        "    if request.GET.get('token') == token:\n"
        "        return 'ok'\n"
    )

    def test_placeholder_fixes_require_manual_review(self):
        from djangosentinel.scanners import ASTScanner
        self.write("views.py", self.VIEWS)
        found = {v.title: v for v in ASTScanner(str(self.root)).scan()}
        for title in ("Timing Attack via == Comparison of Secret/Token",
                      "Insecure random Module Used for Security-Sensitive Value"):
            self.assertIn(title, found)
            self.assertTrue(found[title].fix.manual_review_required, title)

    def test_auto_fix_never_changes_these_files(self):
        from djangosentinel.fixers import AutoFixer
        from djangosentinel.scanners import ASTScanner
        self.write("views.py", self.VIEWS)
        vulns = ASTScanner(str(self.root)).scan()
        AutoFixer(str(self.root)).apply_fixes(vulns)
        self.assertEqual((self.root / "views.py").read_text(encoding="utf-8"), self.VIEWS)

    def test_autoescape_fix_keeps_tags_balanced(self):
        from djangosentinel.fixers import AutoFixer
        from djangosentinel.scanners import DjangoScanner
        self.write("t.html", "{% autoescape off %}{{ body }}{% endautoescape %}\n")
        vulns = [v for v in DjangoScanner(str(self.root)).scan() if "Auto-Escaping" in v.title]
        self.assertTrue(vulns)
        AutoFixer(str(self.root)).apply_fixes(vulns)
        text = (self.root / "t.html").read_text(encoding="utf-8")
        self.assertIn("{% autoescape on %}", text)
        self.assertIn("{% endautoescape %}", text)
        self.assertNotIn("autoescape off", text)

    def test_literal_settings_fix_still_applies(self):
        from djangosentinel.fixers import AutoFixer
        from djangosentinel.scanners import DjangoScanner
        self.write("settings.py", "DEBUG = True\n")
        vulns = [v for v in DjangoScanner(str(self.root)).scan() if v.fix and not v.fix.manual_review_required]
        AutoFixer(str(self.root)).apply_fixes(vulns)
        self.assertIn("DEBUG = False", (self.root / "settings.py").read_text(encoding="utf-8"))


class TestPackageExports(unittest.TestCase):
    def test_every_public_name_resolves(self):
        import djangosentinel
        missing = [n for n in djangosentinel.__all__ if not hasattr(djangosentinel, n)]
        self.assertEqual(missing, [])

    def test_star_import_works(self):
        ns = {}
        exec("from djangosentinel import *", ns)
        self.assertIn("DjangoScanner", ns)
        self.assertIn("AIPatternScanner", ns)


class TestAIProviders(unittest.TestCase):
    KEYS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "SENTINEL_AI_PROVIDER")

    def _env(self, **kw):
        base = {k: "" for k in self.KEYS}
        base.update(kw)
        return mock.patch.dict(os.environ, base)

    def test_selects_provider_with_a_key(self):
        from djangosentinel.ai_model_providers import select_provider, OpenAIProvider, GeminiProvider
        with self._env(OPENAI_API_KEY="k"):
            self.assertIsInstance(select_provider(), OpenAIProvider)
        with self._env(GOOGLE_API_KEY="k"):
            self.assertIsInstance(select_provider(), GeminiProvider)

    def test_explicit_choice_wins(self):
        from djangosentinel.ai_model_providers import select_provider, OpenAIProvider
        with self._env(ANTHROPIC_API_KEY="a", OPENAI_API_KEY="o", SENTINEL_AI_PROVIDER="openai"):
            self.assertIsInstance(select_provider(), OpenAIProvider)

    def test_no_keys_means_unavailable_not_crash(self):
        from djangosentinel.ai_model_providers import select_provider
        with self._env():
            self.assertFalse(select_provider().available)

    def test_gemini_request_has_model_in_url_and_system_instruction(self):
        from djangosentinel.ai_model_providers import GeminiProvider
        seen = {}

        class FakeResp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self):
                return json.dumps({"candidates": [{"content": {"parts": [{"text": "hi"}]}}]}).encode()

        def fake_urlopen(req, timeout=0):
            seen["url"] = req.full_url
            seen["headers"] = {k.lower(): v for k, v in req.header_items()}
            seen["body"] = json.loads(req.data)
            return FakeResp()

        with self._env(GOOGLE_API_KEY="secret-key"):
            provider = GeminiProvider()
            with mock.patch("urllib.request.urlopen", fake_urlopen):
                out = provider.generate("be brief", "hello", 100)
        self.assertEqual(out, "hi")
        self.assertRegex(seen["url"], r"/models/[\w.\-]+:generateContent$")
        self.assertNotIn("secret-key", seen["url"])          # key travels in a header
        self.assertEqual(seen["headers"]["x-goog-api-key"], "secret-key")
        self.assertEqual(seen["body"]["systemInstruction"]["parts"][0]["text"], "be brief")
        self.assertEqual(seen["body"]["generationConfig"]["maxOutputTokens"], 100)


if __name__ == "__main__":
    unittest.main()
