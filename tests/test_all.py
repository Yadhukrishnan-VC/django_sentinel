"""
DjangoSentinel Test Suite
Tests for all scanner types, fixers, and reporters.
"""

import os
import sys
import tempfile
import shutil
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from djangosentinel.scanners import DjangoScanner, BusinessLogicScanner, DependencyScanner
from djangosentinel.fixers import AutoFixer
from djangosentinel.reporters import TerminalReporter, JSONReporter
from djangosentinel.models import Severity, VulnCategory


class TestDjangoScanner(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.settings_file = Path(self.test_dir) / "settings.py"

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def write_file(self, name: str, content: str) -> Path:
        p = Path(self.test_dir) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return p

    def scan(self):
        return DjangoScanner(self.test_dir).scan()

    def test_detects_debug_true(self):
        self.write_file("settings.py", "DEBUG = True\n")
        vulns = self.scan()
        self.assertTrue(any("DEBUG" in v.title for v in vulns))

    def test_no_false_positive_debug_false(self):
        self.write_file("settings.py", "DEBUG = False\n")
        vulns = self.scan()
        self.assertFalse(any("DEBUG=True" in v.title for v in vulns))

    def test_detects_weak_secret_key(self):
        self.write_file("settings.py", "SECRET_KEY = 'django-insecure-abc123'\n")
        vulns = self.scan()
        self.assertTrue(any("SECRET_KEY" in v.title for v in vulns))

    def test_detects_allowed_hosts_wildcard(self):
        self.write_file("settings.py", "ALLOWED_HOSTS = ['*']\n")
        vulns = self.scan()
        self.assertTrue(any("ALLOWED_HOSTS" in v.title for v in vulns))

    def test_detects_session_cookie_insecure(self):
        self.write_file("settings.py", "SESSION_COOKIE_SECURE = False\n")
        vulns = self.scan()
        self.assertTrue(any("Session Cookie" in v.title for v in vulns))

    def test_detects_sql_injection(self):
        self.write_file("views.py",
            "sql = f\"SELECT * FROM users WHERE id={user_id}\"\n"
        )
        vulns = self.scan()
        self.assertTrue(any("SQL Injection" in v.title for v in vulns))

    def test_detects_csrf_exempt(self):
        self.write_file("views.py", "@csrf_exempt\ndef my_view(request): pass\n")
        vulns = self.scan()
        self.assertTrue(any("CSRF" in v.title for v in vulns))

    def test_detects_open_redirect(self):
        self.write_file("views.py",
            "return redirect(request.GET['next'])\n"
        )
        vulns = self.scan()
        self.assertTrue(any("Redirect" in v.title for v in vulns))

    def test_detects_mass_assignment(self):
        self.write_file("forms.py", "fields = '__all__'\n")
        vulns = self.scan()
        self.assertTrue(any("Mass Assignment" in v.title for v in vulns))

    def test_detects_shell_true(self):
        self.write_file("views.py",
            "subprocess.run('ls', shell=True)\n"
        )
        vulns = self.scan()
        self.assertTrue(any("shell=True" in v.title for v in vulns))

    def test_detects_idor(self):
        self.write_file("views.py",
            "obj = Model.objects.get(pk=request.GET['id'])\n"
        )
        vulns = self.scan()
        self.assertTrue(any("IDOR" in v.title for v in vulns))

    def test_detects_hardcoded_password(self):
        self.write_file("config.py", "password = 'supersecret123'\n")
        vulns = self.scan()
        self.assertTrue(any("Hardcoded" in v.title for v in vulns))

    def test_detects_eval(self):
        self.write_file("utils.py", "result = eval(user_input)\n")
        vulns = self.scan()
        self.assertTrue(any("eval" in v.title for v in vulns))

    def test_detects_pickle_loads(self):
        self.write_file("views.py", "pickle.loads(data)\n")
        vulns = self.scan()
        self.assertTrue(any("pickle" in v.title.lower() for v in vulns))

    def test_detects_xss_autoescape_off(self):
        self.write_file("autoescape_test.html", "{% autoescape off %}\n")
        vulns = self.scan()
        titles = " ".join(v.title.lower() for v in vulns)
        self.assertTrue(
            "xss" in titles or "autoescape" in titles or "auto-escaping" in titles,
            f"Expected autoescape vuln, got: {[v.title for v in vulns]}"
        )

    def test_detects_ssti(self):
        self.write_file("views.py",
            "t = Template(f'<p>{user_input}</p>')\n"
        )
        vulns = self.scan()
        self.assertTrue(any("Template Injection" in v.title for v in vulns))

    def test_detects_mark_safe_xss(self):
        self.write_file("views.py",
            "safe_html = mark_safe(request.GET['html'])\n"
        )
        vulns = self.scan()
        self.assertTrue(any("XSS" in v.title or "mark_safe" in v.title.lower() for v in vulns))

    def test_severity_critical_for_debug(self):
        self.write_file("settings.py", "DEBUG = True\n")
        vulns = self.scan()
        debug_vulns = [v for v in vulns if "DEBUG" in v.title]
        self.assertTrue(any(v.severity == Severity.CRITICAL for v in debug_vulns))


class TestBusinessLogicScanner(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def write_file(self, name: str, content: str):
        p = Path(self.test_dir) / name
        p.write_text(content)

    def scan(self):
        return BusinessLogicScanner(self.test_dir).scan()

    def test_detects_race_condition(self):
        self.write_file("views.py",
            "if user.balance >= 100:\n    user.balance -= 100\n"
        )
        vulns = self.scan()
        self.assertTrue(any("Race Condition" in v.title for v in vulns))

    def test_no_race_condition_with_atomic(self):
        self.write_file("views.py",
            "with transaction.atomic():\n    account = Account.objects.select_for_update().get(pk=pk)\n    if account.balance >= amount:\n        pass\n"
        )
        vulns = self.scan()
        race_vulns = [v for v in vulns if "Race Condition" in v.title]
        # Should find fewer or none with atomic
        self.assertLessEqual(len(race_vulns), 1)

    def test_detects_float_currency(self):
        self.write_file("views.py", "price = float(request.POST['price'])\n")
        vulns = self.scan()
        self.assertTrue(any("Float" in v.title or "Decimal" in v.description for v in vulns))

    def test_detects_privilege_escalation(self):
        self.write_file("views.py",
            "user.is_staff = request.POST['is_staff']\n"
        )
        vulns = self.scan()
        self.assertTrue(any("Privilege" in v.title for v in vulns))

    def test_detects_workflow_bypass(self):
        self.write_file("views.py", "order.status = 'paid'\n")
        vulns = self.scan()
        self.assertTrue(any("Workflow" in v.title or "State" in v.title for v in vulns))

    def test_detects_coupon_abuse(self):
        self.write_file("views.py",
            "coupon = Coupon.objects.get(code=code)\n"
            "if coupon.active:\n    cart.discount = coupon.amount\n"
        )
        vulns = self.scan()
        self.assertTrue(any("Coupon" in v.title for v in vulns))


class TestDependencyScanner(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def write_req(self, content: str):
        (Path(self.test_dir) / "requirements.txt").write_text(content)

    def scan(self):
        return DependencyScanner(self.test_dir).scan()

    def test_detects_vulnerable_django(self):
        self.write_req("Django==3.1.0\n")
        vulns = self.scan()
        self.assertTrue(any("Django" in v.title or "django" in v.title.lower() for v in vulns))

    def test_detects_vulnerable_pillow(self):
        self.write_req("Pillow==8.3.0\n")
        vulns = self.scan()
        self.assertTrue(any("Pillow" in v.title for v in vulns))

    def test_detects_vulnerable_pyyaml(self):
        self.write_req("PyYAML==5.4.1\n")
        vulns = self.scan()
        self.assertTrue(any("PyYAML" in v.title or "YAML" in v.title for v in vulns))

    def test_no_false_positive_safe_version(self):
        self.write_req("Pillow==10.2.0\n")
        vulns = self.scan()
        pillow_vulns = [v for v in vulns if "Pillow" in v.title]
        self.assertEqual(len(pillow_vulns), 0)

    def test_detects_dangerous_pickle_import(self):
        py_file = Path(self.test_dir) / "utils.py"
        py_file.write_text("import pickle\npickle.loads(data)\n")
        vulns = self.scan()
        self.assertTrue(any("pickle" in v.title.lower() for v in vulns))


class TestAutoFixer(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_fix_debug_setting(self):
        settings = Path(self.test_dir) / "settings.py"
        settings.write_text("DEBUG = True\nSECRET_KEY = 'abc'\n")

        scanner = DjangoScanner(self.test_dir)
        vulns = scanner.scan()

        fixer = AutoFixer(self.test_dir, dry_run=False, backup=False)
        fixed, skipped = fixer.apply_fixes(vulns)

        # Check file was modified
        new_content = settings.read_text()
        self.assertIn("DEBUG = False", new_content)

    def test_dry_run_does_not_modify(self):
        settings = Path(self.test_dir) / "settings.py"
        original = "DEBUG = True\n"
        settings.write_text(original)

        scanner = DjangoScanner(self.test_dir)
        vulns = scanner.scan()

        fixer = AutoFixer(self.test_dir, dry_run=True, backup=False)
        fixer.apply_fixes(vulns)

        # File should be unchanged
        self.assertEqual(settings.read_text(), original)


class TestReporters(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.settings_file = Path(self.test_dir) / "settings.py"
        self.settings_file.write_text(
            "DEBUG = True\nSESSION_COOKIE_SECURE = False\n"
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def get_result(self):
        import uuid, time
        from djangosentinel.models import ScanResult
        vulns = DjangoScanner(self.test_dir).scan()
        return ScanResult(
            scan_id=str(uuid.uuid4())[:8],
            project_path=self.test_dir,
            files_scanned=1,
            vulnerabilities=vulns,
            scan_duration_seconds=0.1,
        )

    def test_terminal_reporter_runs(self):
        result = self.get_result()
        reporter = TerminalReporter(no_color=True)
        output = reporter.report(result)
        self.assertIn("DJANGO SENTINEL", output)
        self.assertIn("VULNERABILITY SUMMARY", output)

    def test_json_reporter_valid_json(self):
        import json
        result = self.get_result()
        reporter = JSONReporter()
        output = reporter.report(result)
        data = json.loads(output)
        self.assertIn("vulnerabilities", data)
        self.assertIn("summary", data)

    def test_json_reporter_has_vulns(self):
        import json
        result = self.get_result()
        reporter = JSONReporter()
        data = json.loads(reporter.report(result))
        self.assertGreater(len(data["vulnerabilities"]), 0)


if __name__ == "__main__":
    print("🛡️  DjangoSentinel Test Suite")
    print("=" * 50)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestDjangoScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestBusinessLogicScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestDependencyScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestAutoFixer))
    suite.addTests(loader.loadTestsFromTestCase(TestReporters))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
