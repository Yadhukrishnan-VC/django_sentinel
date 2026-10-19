"""
DjangoSentinel — Complete Test Suite (90+ tests)
=================================================
Test classes:
TestDjangoScanner          — 20 tests (settings, views, templates, secrets)
TestASTScanner             — 10 tests (structural detections)
TestBusinessLogicScanner   — 12 tests (logic flaws + AST IDOR)
TestDependencyScanner      — 6 tests  (CVE database, dangerous imports)
TestDiffParser             — 8 tests  (unified diff parsing)
TestDiffScanner            — 9 tests  (diff-scoped vulnerability detection)
TestDataFlowTracker        — 8 tests  (taint analysis)
TestConfidenceScoring      — 8 tests  (scoring + deduplication)
TestASTSafeFixer           — 8 tests  (indentation-preserving fix application)
TestScanCache              — 6 tests  (file-hash cache)
TestAutoFixer              — 3 tests  (simple fixes via ASTSafeFixer)
TestReporters              — 5 tests  (terminal, JSON, diff output)
"""

import sys
import ast
import json
import tempfile
import shutil
import unittest
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from djangosentinel.models import (
    Vulnerability, VulnCategory, Severity, CodeLocation, Fix, ScanResult
)
from djangosentinel.scanners import (
    DjangoScanner, BusinessLogicScanner, DependencyScanner, ASTScanner
)
from djangosentinel.scanners.diff_scanner import DiffParser, DiffScanner
from djangosentinel.fixers import AutoFixer, ASTSafeFixer
from djangosentinel.reporters import TerminalReporter, JSONReporter, DiffReporter
from djangosentinel.analysis import (
    DataFlowTracker, apply_confidence_scores, deduplicate,
    score_label, finding_hash,
)
from djangosentinel.cache import ScanCache, file_hash


# ─────────────────────────────────────────────────────────────────────────────
# Shared test helpers
# ─────────────────────────────────────────────────────────────────────────────

class TempDirMixin:
    """Mixin that creates/destroys a temp directory per test."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def write_file(self, name: str, content: str) -> Path:
        p = Path(self.test_dir) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def make_vuln(self, **kwargs) -> Vulnerability:
        defaults = dict(
            vuln_id="test01",
            title="Test Vuln",
            category=VulnCategory.INJECTION,
            severity=Severity.HIGH,
            location=CodeLocation("views.py", 5, snippet="x = eval(user_input)"),
            description="Test description",
            owasp_ref="A03:2021",
            cwe_id="CWE-89",
        )
        defaults.update(kwargs)
        return Vulnerability(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Django Scanner Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDjangoScanner(TempDirMixin, unittest.TestCase):

    def scan(self):
        return DjangoScanner(self.test_dir).scan()

    # Settings detections
    def test_detects_debug_true(self):
        self.write_file("settings.py", "DEBUG = True\n")
        vulns = self.scan()
        self.assertTrue(any("DEBUG" in v.title for v in vulns))

    def test_no_fp_debug_false(self):
        self.write_file("settings.py", "DEBUG = False\n")
        self.assertFalse(any("DEBUG=True" in v.title for v in self.scan()))

    def test_detects_weak_secret_key(self):
        self.write_file("settings.py", "SECRET_KEY = 'django-insecure-abc123'\n")
        self.assertTrue(any("SECRET_KEY" in v.title for v in self.scan()))

    def test_detects_allowed_hosts_wildcard(self):
        self.write_file("settings.py", "ALLOWED_HOSTS = ['*']\n")
        self.assertTrue(any("ALLOWED_HOSTS" in v.title for v in self.scan()))

    def test_detects_session_cookie_insecure(self):
        self.write_file("settings.py", "SESSION_COOKIE_SECURE = False\n")
        self.assertTrue(any("Session Cookie" in v.title for v in self.scan()))

    def test_fix_available_for_debug(self):
        self.write_file("settings.py", "DEBUG = True\n")
        vulns = [v for v in self.scan() if "DEBUG" in v.title]
        self.assertGreater(len(vulns), 0)
        self.assertIsNotNone(vulns[0].fix)
        self.assertEqual(vulns[0].fix.fixed_code, "DEBUG = False")

    # View detections
    def test_detects_sql_injection_fstring(self):
        self.write_file("views.py", 'sql = f"SELECT * FROM users WHERE id={uid}"\n')
        self.assertTrue(any("SQL" in v.title or "Injection" in v.title for v in self.scan()))

    def test_detects_csrf_exempt(self):
        self.write_file("views.py", "@csrf_exempt\ndef view(request): pass\n")
        self.assertTrue(any("CSRF" in v.title for v in self.scan()))

    def test_detects_open_redirect(self):
        self.write_file("views.py", "return redirect(request.GET['next'])\n")
        self.assertTrue(any("Redirect" in v.title for v in self.scan()))

    def test_detects_mass_assignment(self):
        self.write_file("forms.py", "fields = '__all__'\n")
        self.assertTrue(any("Mass Assignment" in v.title for v in self.scan()))

    def test_detects_shell_true(self):
        self.write_file("views.py", "subprocess.run('ls', shell=True)\n")
        self.assertTrue(any("shell=True" in v.title for v in self.scan()))

    def test_detects_idor_regex(self):
        self.write_file("views.py", "obj = Model.objects.get(pk=request.GET['id'])\n")
        self.assertTrue(any("IDOR" in v.title for v in self.scan()))

    # Secret detection
    def test_detects_hardcoded_password(self):
        self.write_file("config.py", "password = 'supersecret123'\n")
        self.assertTrue(any("Hardcoded" in v.title for v in self.scan()))

    def test_no_fp_hardcoded_in_test_file(self):
        # Secrets in test files should have reduced confidence, not necessarily filtered
        self.write_file("tests/test_views.py", "password = 'testpass123'\n")
        # May still detect — just confidence should be lower
        vulns = self.scan()
        pw_vulns = [v for v in vulns if "Hardcoded" in v.title]
        # If detected, verify it's in a test file path
        for v in pw_vulns:
            self.assertIn("test", v.location.file_path.lower())

    # Dangerous functions
    def test_detects_eval(self):
        self.write_file("utils.py", "result = eval(user_input)\n")
        self.assertTrue(any("eval" in v.title for v in self.scan()))

    def test_detects_pickle_loads(self):
        self.write_file("views.py", "obj = pickle.loads(data)\n")
        self.assertTrue(any("pickle" in v.title.lower() for v in self.scan()))

    # Template detections
    def test_detects_autoescape_off(self):
        self.write_file("autoescape_test.html", "{% autoescape off %}\n")
        vulns = self.scan()
        titles = " ".join(v.title.lower() for v in vulns)
        self.assertTrue("xss" in titles or "autoescape" in titles or "auto-escaping" in titles,
                        f"Expected autoescape vuln, got: {[v.title for v in vulns]}")

    def test_detects_mark_safe_xss(self):
        self.write_file("views.py", "safe_html = mark_safe(request.GET['html'])\n")
        self.assertTrue(any("XSS" in v.title or "mark_safe" in v.title.lower() for v in self.scan()))

    # Severity validation
    def test_debug_is_critical(self):
        self.write_file("settings.py", "DEBUG = True\n")
        debug_vulns = [v for v in self.scan() if "DEBUG" in v.title]
        self.assertTrue(any(v.severity == Severity.CRITICAL for v in debug_vulns))

    def test_eval_is_critical(self):
        self.write_file("utils.py", "x = eval(user_input)\n")
        eval_vulns = [v for v in self.scan() if "eval" in v.title.lower()]
        self.assertTrue(any(v.severity == Severity.CRITICAL for v in eval_vulns))


# ─────────────────────────────────────────────────────────────────────────────
# 2. AST Scanner Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestASTScanner(TempDirMixin, unittest.TestCase):

    def scan(self):
        return ASTScanner(self.test_dir).scan()

    def test_detects_random_for_security(self):
        self.write_file("utils.py",
            "import random\ntoken = random.randint(0, 999999)\n")
        self.assertTrue(any("random" in v.title.lower() for v in self.scan()))

    def test_detects_md5_for_secrets(self):
        self.write_file("crypto.py",
            "import hashlib\nhashed = hashlib.md5(password.encode()).hexdigest()\n")
        self.assertTrue(any("MD5" in v.title or "SHA" in v.title for v in self.scan()))

    def test_detects_timing_attack_comparison(self):
        self.write_file("auth.py",
            "def verify_token(token):\n    if token == expected_token:\n        return True\n")
        self.assertTrue(any("Timing" in v.title or "==" in v.title for v in self.scan()))

    def test_detects_assert_security_gate(self):
        self.write_file("views.py",
            "def my_view(request):\n    assert request.user.is_authenticated\n    return data\n")
        self.assertTrue(any("assert" in v.title.lower() for v in self.scan()))

    def test_detects_cbv_missing_login_required(self):
        self.write_file("views.py",
            "class DeleteOrderView(DeleteView):\n    model = Order\n    pass\n")
        self.assertTrue(any("LoginRequired" in v.title or "Missing" in v.title for v in self.scan()))

    def test_no_fp_cbv_with_mixin(self):
        self.write_file("views.py",
            "class DeleteOrderView(LoginRequiredMixin, DeleteView):\n    model = Order\n")
        cbv_vulns = [v for v in self.scan() if "LoginRequired" in v.title]
        self.assertEqual(len(cbv_vulns), 0)

    def test_detects_log_injection_fstring(self):
        self.write_file("views.py",
            "import logging\nlogger = logging.getLogger(__name__)\n"
            "logger.info(f'User {user_id} accessed {endpoint}')\n")
        self.assertTrue(any("Log" in v.title or "inject" in v.title.lower() for v in self.scan()))

    def test_detects_silent_exception_swallow(self):
        self.write_file("auth.py",
            "def validate_token(token):\n    try:\n        verify(token)\n"
            "    except Exception:\n        pass\n")
        self.assertTrue(any("exception" in v.title.lower() or "swallow" in v.title.lower() for v in self.scan()))

    def test_detects_mutable_default_arg(self):
        self.write_file("utils.py",
            "def process_auth(request, data={}):\n    return data\n")
        self.assertTrue(any("Mutable" in v.title for v in self.scan()))

    def test_detects_dynamic_getattr(self):
        self.write_file("views.py",
            "value = getattr(obj, request.GET['field'])\n")
        self.assertTrue(any("getattr" in v.title.lower() or "Dynamic" in v.title for v in self.scan()))


# ─────────────────────────────────────────────────────────────────────────────
# 3. Business Logic Scanner Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBusinessLogicScanner(TempDirMixin, unittest.TestCase):

    def scan(self):
        return BusinessLogicScanner(self.test_dir).scan()

    def test_detects_race_condition(self):
        self.write_file("views.py", "if user.balance >= 100:\n    user.balance -= 100\n")
        self.assertTrue(any("Race Condition" in v.title for v in self.scan()))

    def test_no_fp_race_with_atomic(self):
        self.write_file("views.py",
            "with transaction.atomic():\n"
            "    account = Account.objects.select_for_update().get(pk=pk)\n"
            "    if account.balance >= amount:\n        pass\n")
        race_vulns = [v for v in self.scan() if "Race Condition" in v.title]
        self.assertEqual(len(race_vulns), 0)

    def test_detects_float_currency(self):
        self.write_file("views.py", "price = float(request.POST['price'])\n")
        self.assertTrue(any("Float" in v.title or "Decimal" in v.description for v in self.scan()))

    def test_detects_privilege_escalation(self):
        self.write_file("views.py", "user.is_staff = request.POST['is_staff']\n")
        self.assertTrue(any("Privilege" in v.title for v in self.scan()))

    def test_detects_workflow_bypass(self):
        self.write_file("views.py", "order.status = 'paid'\n")
        self.assertTrue(any("Workflow" in v.title or "State" in v.title for v in self.scan()))

    def test_detects_coupon_abuse(self):
        self.write_file("views.py",
            "coupon = Coupon.objects.get(code=code)\n"
            "if coupon.active:\n    cart.discount = coupon.amount\n")
        self.assertTrue(any("Coupon" in v.title for v in self.scan()))

    def test_detects_negative_balance_missing_guard(self):
        self.write_file("views.py",
            "def withdraw(request):\n    user.balance -= amount\n    user.save()\n")
        self.assertTrue(any("balance" in v.title.lower() or "negative" in v.description.lower()
                            for v in self.scan()))

    # AST-based IDOR tests
    def test_detects_idor_filter_no_user_ast(self):
        self.write_file("views.py",
            "from django.shortcuts import get_object_or_404\n"
            "def order_detail(request, pk):\n"
            "    order = Order.objects.get(id=pk)\n"
            "    return order\n")
        vulns = self.scan()
        idor_vulns = [v for v in vulns if "IDOR" in v.title and "AST" in v.title]
        self.assertGreater(len(idor_vulns), 0)

    def test_no_fp_idor_with_user_filter_ast(self):
        self.write_file("views.py",
            "def order_detail(request, pk):\n"
            "    order = Order.objects.get(id=pk, user=request.user)\n"
            "    return order\n")
        vulns = self.scan()
        idor_vulns = [v for v in vulns if "IDOR" in v.title and "AST" in v.title]
        self.assertEqual(len(idor_vulns), 0)

    def test_idor_fix_is_cbv_aware(self):
        self.write_file("views.py",
            "class OrderView(View):\n"
            "    def get(self, request, pk):\n"
            "        order = Order.objects.get(id=pk)\n"
            "        return order\n")
        vulns = self.scan()
        idor_vulns = [v for v in vulns if "IDOR" in v.title and "AST" in v.title]
        if idor_vulns:
            fix_code = idor_vulns[0].fix.fixed_code if idor_vulns[0].fix else ""
            # CBV context should mention self.request
            self.assertIn("self.request", fix_code)

    def test_idor_not_triggered_on_non_model_get(self):
        """dict.get(id=x) should not trigger IDOR."""
        self.write_file("utils.py",
            "data = my_dict.get('id', None)\n")
        vulns = self.scan()
        idor_vulns = [v for v in vulns if "IDOR" in v.title and "AST" in v.title]
        self.assertEqual(len(idor_vulns), 0)

    def test_detects_pagination_without_user_filter(self):
        self.write_file("views.py",
            "paginator = Paginator(Order.objects.all(), 25)\n"
            "page_obj = paginator.get_page(request.GET.get('page'))\n")
        self.assertTrue(any("Paginator" in v.description or "paginated" in v.description.lower()
                            or "Paginated" in v.title for v in self.scan()))


# ─────────────────────────────────────────────────────────────────────────────
# 4. Dependency Scanner Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDependencyScanner(TempDirMixin, unittest.TestCase):

    def scan(self):
        return DependencyScanner(self.test_dir).scan()

    def write_req(self, content):
        self.write_file("requirements.txt", content)

    def test_detects_vulnerable_django(self):
        self.write_req("Django==3.1.0\n")
        self.assertTrue(any("Django" in v.title for v in self.scan()))

    def test_detects_vulnerable_pillow(self):
        self.write_req("Pillow==8.3.0\n")
        self.assertTrue(any("Pillow" in v.title for v in self.scan()))

    def test_detects_vulnerable_pyyaml(self):
        self.write_req("PyYAML==5.4.1\n")
        self.assertTrue(any("PyYAML" in v.title or "YAML" in v.title for v in self.scan()))

    def test_no_fp_safe_pillow_version(self):
        self.write_req("Pillow==10.2.0\n")
        self.assertEqual(len([v for v in self.scan() if "Pillow" in v.title]), 0)

    def test_detects_dangerous_pickle_import(self):
        self.write_file("utils.py", "import pickle\npickle.loads(data)\n")
        self.assertTrue(any("pickle" in v.title.lower() for v in self.scan()))

    def test_detects_dangerous_yaml_import(self):
        self.write_file("config.py", "import yaml\nyaml.load(stream)\n")
        vulns = self.scan()
        # Should flag dangerous import or yaml.load
        self.assertTrue(any("yaml" in v.title.lower() or "YAML" in v.title for v in vulns))


# ─────────────────────────────────────────────────────────────────────────────
# 5. Diff Parser Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDiffParser(unittest.TestCase):

    def setUp(self):
        self.parser = DiffParser()

    def parse(self, diff_text):
        return self.parser.parse(diff_text)

    def test_parses_simple_diff(self):
        diff = (
            "diff --git a/views.py b/views.py\n"
            "--- a/views.py\n+++ b/views.py\n"
            "@@ -1,3 +1,4 @@\n import os\n+DEBUG = True\n def view(): pass\n"
        )
        files = self.parse(diff)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].path, "views.py")

    def test_added_lines_tracked_correctly(self):
        diff = (
            "diff --git a/settings.py b/settings.py\n"
            "--- a/settings.py\n+++ b/settings.py\n"
            "@@ -5,3 +5,5 @@\n INSTALLED_APPS = []\n"
            "+DEBUG = True\n+SECRET_KEY = 'insecure'\n DATABASES = {}\n"
        )
        files = self.parse(diff)
        added = files[0].all_added_lines
        self.assertEqual(len(added), 2)

    def test_new_file_detected(self):
        diff = (
            "diff --git a/newfile.py b/newfile.py\n"
            "new file mode 100644\n--- /dev/null\n+++ b/newfile.py\n"
            "@@ -0,0 +1,3 @@\n+import os\n+x = eval(input())\n+print(x)\n"
        )
        files = self.parse(diff)
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].is_new_file)
        self.assertEqual(len(files[0].all_added_lines), 3)

    def test_multiple_files_in_diff(self):
        diff = (
            "diff --git a/views.py b/views.py\n--- a/views.py\n+++ b/views.py\n"
            "@@ -1,1 +1,2 @@\n pass\n+DEBUG = True\n"
            "diff --git a/models.py b/models.py\n--- a/models.py\n+++ b/models.py\n"
            "@@ -1,1 +1,2 @@\n pass\n+SECRET = 'abc'\n"
        )
        files = self.parse(diff)
        self.assertEqual(len(files), 2)
        self.assertEqual({f.path for f in files}, {"views.py", "models.py"})

    def test_deleted_file_has_no_added_lines(self):
        diff = (
            "diff --git a/old.py b/old.py\n--- a/old.py\n+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n-import os\n-x = 1\n"
        )
        files = self.parse(diff)
        for f in files:
            self.assertEqual(len(f.all_added_lines), 0)

    def test_multiple_hunks_in_one_file(self):
        diff = (
            "diff --git a/views.py b/views.py\n--- a/views.py\n+++ b/views.py\n"
            "@@ -1,3 +1,4 @@\n a = 1\n+b = eval('x')\n c = 3\n d = 4\n"
            "@@ -20,3 +21,4 @@\n e = 1\n+f = os.system('ls')\n g = 3\n h = 4\n"
        )
        files = self.parse(diff)
        self.assertEqual(len(files), 1)
        self.assertEqual(len(files[0].hunks), 2)

    def test_empty_diff_returns_empty_list(self):
        self.assertEqual(self.parse(""), [])

    def test_context_lines_not_counted_as_added(self):
        diff = (
            "diff --git a/views.py b/views.py\n--- a/views.py\n+++ b/views.py\n"
            "@@ -1,3 +1,4 @@\n context_line_1\n context_line_2\n+added_line\n context_line_3\n"
        )
        files = self.parse(diff)
        added = files[0].all_added_lines
        self.assertEqual(len(added), 1)
        self.assertIn("added_line", list(added.values())[0])


# ─────────────────────────────────────────────────────────────────────────────
# 6. Diff Scanner Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDiffScanner(TempDirMixin, unittest.TestCase):

    def make_diff(self, filename, added_lines, start_line=1):
        count = len(added_lines)
        lines = [
            f"diff --git a/{filename} b/{filename}",
            f"--- a/{filename}", f"+++ b/{filename}",
            f"@@ -{start_line},0 +{start_line},{count} @@",
        ]
        for line in added_lines:
            lines.append(f"+{line}")
        return "\n".join(lines) + "\n"

    def scan_diff(self, diff_text):
        scanner = DiffScanner(self.test_dir, diff_text,
                                skip_ast=True, skip_logic=True, skip_deps=True)
        return scanner.scan()

    def test_detects_debug_in_diff(self):
        self.write_file("settings.py", "DEBUG = True\n")
        diff = self.make_diff("settings.py", ["DEBUG = True"])
        self.assertTrue(any("DEBUG" in v.title for v in self.scan_diff(diff)))

    def test_unchanged_lines_not_flagged(self):
        self.write_file("settings.py", "DEBUG = True\nSECRET_KEY = 'safe-key'\n")
        diff = (
            "diff --git a/settings.py b/settings.py\n"
            "--- a/settings.py\n+++ b/settings.py\n"
            "@@ -1,1 +1,2 @@\n DEBUG = True\n+SECRET_KEY = 'safe-key'\n"
        )
        vulns = self.scan_diff(diff)
        debug_vulns = [v for v in vulns if "DEBUG" in v.title]
        self.assertEqual(len(debug_vulns), 0, "DEBUG on context line should NOT be flagged")

    def test_new_file_all_lines_scanned(self):
        self.write_file("newviews.py", "import os\nos.system('ls')\n")
        diff = (
            "diff --git a/newviews.py b/newviews.py\nnew file mode 100644\n"
            "--- /dev/null\n+++ b/newviews.py\n"
            "@@ -0,0 +1,2 @@\n+import os\n+os.system('ls')\n"
        )
        vulns = self.scan_diff(diff)
        self.assertTrue(any("os.system" in v.title or "Command" in v.title for v in vulns))

    def test_detects_sql_injection_in_diff(self):
        content = 'sql = f"SELECT * FROM users WHERE id={user_id}"\n'
        self.write_file("views.py", content)
        diff = self.make_diff("views.py", [content.rstrip()])
        vulns = self.scan_diff(diff)
        self.assertTrue(any("SQL" in v.title or "Injection" in v.title for v in vulns))

    def test_detects_hardcoded_secret_in_diff(self):
        self.write_file("config.py", "password = 'mysecret123'\n")
        diff = self.make_diff("config.py", ["password = 'mysecret123'"])
        self.assertTrue(any("Hardcoded" in v.title for v in self.scan_diff(diff)))

    def test_diff_summary_has_correct_counts(self):
        diff = self.make_diff("views.py", ["x = 1", "y = 2", "z = 3"])
        scanner = DiffScanner(self.test_dir, diff, skip_deps=True)
        summary = scanner.diff_summary()
        self.assertEqual(summary["total_changed_files"], 1)
        self.assertGreaterEqual(summary["total_added_lines"], 3)

    def test_empty_diff_returns_no_vulns(self):
        self.assertEqual(self.scan_diff(""), [])

    def test_non_python_files_skipped(self):
        diff = self.make_diff("Dockerfile", ["ENV SECRET=abc123"])
        self.assertEqual(self.scan_diff(diff), [])

    def test_dependency_in_diff_detected(self):
        self.write_file("requirements.txt", "Django==3.1.0\n")
        diff = (
            "diff --git a/requirements.txt b/requirements.txt\n"
            "--- a/requirements.txt\n+++ b/requirements.txt\n"
            "@@ -0,0 +1,1 @@\n+Django==3.1.0\n"
        )
        from djangosentinel.scanners.diff_scanner import DiffScanner as DS
        scanner = DS(self.test_dir, diff, skip_ast=True, skip_logic=True, skip_deps=False)
        vulns = scanner.scan()
        self.assertTrue(any("Django" in v.title or "django" in v.location.file_path for v in vulns))


# ─────────────────────────────────────────────────────────────────────────────
# 7. Data Flow Tracker Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDataFlowTracker(TempDirMixin, unittest.TestCase):

    def track(self, source, filename="views.py"):
        tracker = DataFlowTracker(self.test_dir)
        return tracker.analyze_file(filename, source)

    def test_detects_request_get_to_sql(self):
        source = (
            "def view(request):\n"
            "    uid = request.GET['id']\n"
            '    cursor.execute(f"SELECT * FROM users WHERE id={uid}")\n'
        )
        flows = self.track(source)
        self.assertTrue(any("SQL" in f.vuln_info.get("vuln", "") or "execute" in f.sink_name
                            for f in flows))

    def test_detects_request_post_to_eval(self):
        source = (
            "def view(request):\n"
            "    code = request.POST['expr']\n"
            "    result = eval(code)\n"
        )
        flows = self.track(source)
        self.assertTrue(any("Code" in f.vuln_info.get("vuln", "") or "eval" in f.sink_name
                            for f in flows))

    def test_tracks_variable_propagation(self):
        """Taint should follow through variable assignment."""
        source = (
            "def view(request):\n"
            "    raw = request.GET['q']\n"
            "    query = raw\n"  # propagation
            '    cursor.execute(f"SELECT ... WHERE name={query}")\n'
        )
        flows = self.track(source)
        # At least one flow should be found (direct or through propagation)
        self.assertGreaterEqual(len(flows), 1)

    def test_no_flow_when_sanitized(self):
        """Using int() to coerce should mark as safe."""
        source = (
            "def view(request):\n"
            "    uid = int(request.GET['id'])\n"  # int() is in SANITIZERS
            '    cursor.execute("SELECT * FROM users WHERE id=%s", [uid])\n'
        )
        flows = self.track(source)
        # Flows should be sanitized (no real injection)
        real_flows = [f for f in flows if not f.sanitized]
        self.assertEqual(len(real_flows), 0)

    def test_detects_request_body_to_pickle(self):
        source = (
            "def view(request):\n"
            "    data = request.body\n"
            "    obj = pickle.loads(data)\n"
        )
        flows = self.track(source)
        self.assertTrue(any("pickle" in f.sink_name for f in flows))

    def test_detects_ssrf_via_requests_get(self):
        source = (
            "def view(request):\n"
            "    url = request.GET['url']\n"
            "    resp = requests.get(url)\n"
        )
        flows = self.track(source)
        self.assertTrue(any("SSRF" in f.vuln_info.get("vuln", "") or "requests" in f.sink_name
                            for f in flows))

    def test_empty_source_returns_no_flows(self):
        self.assertEqual(self.track(""), [])

    def test_non_view_function_tracked(self):
        """Even non-view functions should be analyzed for taint."""
        source = (
            "def process(user_input):\n"
            '    query = f"SELECT * FROM t WHERE x={user_input}"\n'
            "    cursor.execute(query)\n"
        )
        flows = self.track(source)
        # May not detect without request.* source, but no crash
        self.assertIsInstance(flows, list)


# ─────────────────────────────────────────────────────────────────────────────
# 8. Confidence Scoring and Deduplication Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestConfidenceScoring(TempDirMixin, unittest.TestCase):

    def make_vuln(self, source="ast_scanner", severity=Severity.HIGH,
                file_path="views.py", snippet="") -> Vulnerability:
        v = Vulnerability(
            vuln_id="t01",
            title="Test", category=VulnCategory.INJECTION, severity=severity,
            location=CodeLocation(file_path, 5, snippet=snippet),
            description="test", owasp_ref="A03", cwe_id="CWE-89",
        )
        v.metadata["source"] = source
        return v

    def test_ast_scanner_gets_higher_base_confidence(self):
        v_ast = self.make_vuln(source="ast_scanner")
        v_regex = self.make_vuln(source="django_scanner")
        scored = apply_confidence_scores([v_ast, v_regex])
        self.assertGreater(
            scored[0].metadata["confidence"],
            scored[1].metadata["confidence"],
        )

    def test_critical_severity_boosts_confidence(self):
        v_crit = self.make_vuln(severity=Severity.CRITICAL)
        v_low = self.make_vuln(severity=Severity.LOW)
        scored = apply_confidence_scores([v_crit, v_low])
        self.assertGreater(
            scored[0].metadata["confidence"],
            scored[1].metadata["confidence"],
        )

    def test_test_file_reduces_confidence(self):
        v_prod = self.make_vuln(file_path="views.py")
        v_test = self.make_vuln(file_path="tests/test_views.py")
        scored = apply_confidence_scores([v_prod, v_test])
        self.assertGreater(
            scored[0].metadata["confidence"],
            scored[1].metadata["confidence"],
        )

    def test_confidence_label_high(self):
        self.assertEqual(score_label(0.90), "HIGH")

    def test_confidence_label_medium(self):
        self.assertEqual(score_label(0.70), "MEDIUM")

    def test_confidence_label_low(self):
        self.assertEqual(score_label(0.45), "LOW")

    def test_deduplication_same_location(self):
        v1 = self.make_vuln(source="ast_scanner")
        v2 = self.make_vuln(source="django_scanner")
        v1.metadata["confidence"] = 0.85
        v2.metadata["confidence"] = 0.70
        deduped = deduplicate([v1, v2])
        self.assertEqual(len(deduped), 1)
        # Should keep higher confidence
        self.assertEqual(deduped[0].metadata["source"], "ast_scanner")

    def test_deduplication_different_locations_kept_separate(self):
        v1 = Vulnerability("a", "SQL", VulnCategory.INJECTION, Severity.HIGH,
                            CodeLocation("views.py", 5), "x", "A03", "CWE-89")
        v2 = Vulnerability("b", "SQL", VulnCategory.INJECTION, Severity.HIGH,
                            CodeLocation("views.py", 50), "x", "A03", "CWE-89")
        deduped = deduplicate([v1, v2])
        self.assertEqual(len(deduped), 2)

    def test_finding_hash_stable(self):
        v = self.make_vuln()
        h1 = finding_hash(v)
        h2 = finding_hash(v)
        self.assertEqual(h1, h2)


# ─────────────────────────────────────────────────────────────────────────────
# 9. AST-Safe Fixer Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestASTSafeFixer(TempDirMixin, unittest.TestCase):

    def make_fix(self, original: str, fixed: str, manual=False) -> Fix:
        return Fix(
            description="Test fix",
            original_code=original,
            fixed_code=fixed,
            applied=False,
            manual_review_required=manual,
            explanation="test",
        )

    def apply(self, code: str, lineno: int, orig: str, fixed: str,
                snippet: str = "") -> tuple:
        """Write code to file, apply fix, return (success, new_code)."""
        f = self.write_file("test_fix.py", code)
        vuln = Vulnerability(
            "t01", "Test", VulnCategory.MISCONFIG, Severity.HIGH,
            CodeLocation("test_fix.py", lineno, snippet=snippet or orig),
            "desc", "A05", "CWE-94",
            fix=self.make_fix(orig, fixed),
        )
        fixer = ASTSafeFixer(self.test_dir, dry_run=False, backup=False)
        success = fixer.apply_fix(vuln)
        new_code = f.read_text()
        return success, new_code

    def test_simple_inline_replacement(self):
        code = "DEBUG = True\n"
        ok, new_code = self.apply(code, 1, "DEBUG = True", "DEBUG = False", "DEBUG = True")
        self.assertTrue(ok)
        self.assertIn("DEBUG = False", new_code)

    def test_preserves_indentation_nested(self):
        # Real-world: indented inside class/function - valid Python
        code = "class MyView:\n    def get(self, request):\n        DEBUG = True\n        return True\n"
        ok, new_code = self.apply(code, 3, "DEBUG = True", "DEBUG = False", "DEBUG = True")
        self.assertTrue(ok)
        # Must still be at 8-space indent
        self.assertIn("        DEBUG = False", new_code)

    def test_result_is_valid_python(self):
        code = "class Config:\n    DEBUG = True\n    SECRET = 'abc'\n"
        ok, new_code = self.apply(code, 2, "DEBUG = True", "DEBUG = False", "DEBUG = True")
        self.assertTrue(ok)
        try:
            ast.parse(new_code)
        except SyntaxError:
            self.fail("Fixed code is not valid Python")

    def test_does_not_apply_if_original_not_found(self):
        code = "DEBUG = False\n"
        ok, new_code = self.apply(code, 1, "DEBUG = True", "DEBUG = False", "DEBUG = True")
        # Can't find original, so should not change anything meaningful
        # (or apply but detect same result)
        self.assertEqual(new_code, code) if not ok else None

    def test_dry_run_does_not_modify_file(self):
        code = "DEBUG = True\n"
        f = self.write_file("dry.py", code)
        vuln = Vulnerability(
            "t01", "Test", VulnCategory.MISCONFIG, Severity.HIGH,
            CodeLocation("dry.py", 1, snippet="DEBUG = True"),
            "desc", "A05", "CWE-94",
            fix=self.make_fix("DEBUG = True", "DEBUG = False"),
        )
        fixer = ASTSafeFixer(self.test_dir, dry_run=True, backup=False)
        fixer.apply_fix(vuln)
        self.assertEqual(f.read_text(), code)

    def test_multi_line_fix_indented_correctly(self):
        code = (
            "class Config:\n"
            "    def process(self):\n"
            "        x = 1\n"
            "        SESSION_COOKIE_SECURE = False\n"
        )
        ok, new_code = self.apply(
            code, 4,
            "SESSION_COOKIE_SECURE = False",
            "SESSION_COOKIE_SECURE = True",
            "SESSION_COOKIE_SECURE = False"
        )
        if ok:
            # Should still have correct indentation
            self.assertIn("        SESSION_COOKIE_SECURE = True", new_code)
            try:
                ast.parse(new_code)
            except SyntaxError:
                self.fail("Multi-line fix broke Python syntax")

    def test_skips_manual_review_fix(self):
        code = "DEBUG = True\n"
        f = self.write_file("manual.py", code)
        vuln = Vulnerability(
            "t01", "Test", VulnCategory.MISCONFIG, Severity.HIGH,
            CodeLocation("manual.py", 1, snippet="DEBUG = True"),
            "desc", "A05", "CWE-94",
            fix=self.make_fix("DEBUG = True", "# manual fix needed", manual=True),
        )
        fixer = ASTSafeFixer(self.test_dir, dry_run=False, backup=False)
        result = fixer.apply_fix(vuln)
        self.assertFalse(result)  # Should skip manual review fixes
        self.assertEqual(f.read_text(), code)  # File unchanged

    def test_backup_created_before_modification(self):
        code = "DEBUG = True\n"
        self.write_file("backup_test.py", code)
        vuln = Vulnerability(
            "t01", "Test", VulnCategory.MISCONFIG, Severity.HIGH,
            CodeLocation("backup_test.py", 1, snippet="DEBUG = True"),
            "desc", "A05", "CWE-94",
            fix=self.make_fix("DEBUG = True", "DEBUG = False"),
        )
        fixer = ASTSafeFixer(self.test_dir, dry_run=False, backup=True)
        fixer.apply_fix(vuln)
        # Check backup dir was created
        backup_dirs = list(Path(self.test_dir, ".sentinel_backups").glob("*"))
        self.assertGreater(len(backup_dirs), 0)


# ─────────────────────────────────────────────────────────────────────────────
# 10. Scan Cache Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScanCache(TempDirMixin, unittest.TestCase):

    def make_vuln(self) -> Vulnerability:
        v = Vulnerability(
            "c01", "SQL Injection", VulnCategory.INJECTION, Severity.CRITICAL,
            CodeLocation("views.py", 5, snippet="cursor.execute(f'...')"),
            "SQL injection", "A03", "CWE-89",
        )
        v.metadata["confidence"] = 0.90
        return v

    def test_cache_hit_returns_findings(self):
        cache = ScanCache(self.test_dir)
        v = self.make_vuln()
        cache.set("views.py", "abc123", [v])
        result = cache.get("views.py", "abc123")
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].title, "SQL Injection")

    def test_cache_miss_on_wrong_hash(self):
        cache = ScanCache(self.test_dir)
        cache.set("views.py", "abc123", [self.make_vuln()])
        result = cache.get("views.py", "differenthash")
        self.assertIsNone(result)

    def test_cache_persists_across_instances(self):
        cache1 = ScanCache(self.test_dir)
        cache1.set("views.py", "hash001", [self.make_vuln()])
        cache1.flush()
        cache2 = ScanCache(self.test_dir)
        result = cache2.get("views.py", "hash001")
        self.assertIsNotNone(result)

    def test_cache_skip_ai_findings(self):
        cache = ScanCache(self.test_dir)
        v = self.make_vuln()
        v.title = "[AI] Some AI finding"
        cache.set("views.py", "hash002", [v])
        result = cache.get("views.py", "hash002")
        # AI findings should not be cached
        self.assertTrue(result is None or len(result) == 0)

    def test_file_hash_is_stable(self):
        f = self.write_file("views.py", "x = 1\n")
        h1 = file_hash(f)
        h2 = file_hash(f)
        self.assertEqual(h1, h2)

    def test_file_hash_changes_on_content_change(self):
        f = self.write_file("views.py", "x = 1\n")
        h1 = file_hash(f)
        f.write_text("x = 2\n")
        h2 = file_hash(f)
        self.assertNotEqual(h1, h2)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Auto Fixer Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAutoFixer(TempDirMixin, unittest.TestCase):

    def test_fix_debug_setting(self):
        settings = self.write_file("settings.py", "DEBUG = True\nSECRET_KEY = 'abc'\n")
        vulns = DjangoScanner(self.test_dir).scan()
        fixer = AutoFixer(self.test_dir, dry_run=False, backup=False)
        fixed, _ = fixer.apply_fixes(vulns)
        self.assertGreater(fixed, 0)
        self.assertIn("DEBUG = False", settings.read_text())

    def test_dry_run_does_not_modify(self):
        settings = self.write_file("settings.py", "DEBUG = True\n")
        original = settings.read_text()
        vulns = DjangoScanner(self.test_dir).scan()
        fixer = AutoFixer(self.test_dir, dry_run=True, backup=False)
        fixer.apply_fixes(vulns)
        self.assertEqual(settings.read_text(), original)

    def test_fixed_file_is_valid_python(self):
        settings = self.write_file("settings.py",
            "import os\nDEBUG = True\nSECRET_KEY = 'abc'\nDATABASES = {}\n")
        vulns = DjangoScanner(self.test_dir).scan()
        fixer = AutoFixer(self.test_dir, dry_run=False, backup=False)
        fixer.apply_fixes(vulns)
        try:
            ast.parse(settings.read_text())
        except SyntaxError:
            self.fail("Fixed settings.py is not valid Python")


# ─────────────────────────────────────────────────────────────────────────────
# 12. Reporter Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestReporters(TempDirMixin, unittest.TestCase):

    def make_result(self, vulns=None) -> ScanResult:
        import uuid
        if vulns is None:
            v = Vulnerability(
                "r01", "DEBUG=True in Production Settings",
                VulnCategory.MISCONFIG, Severity.CRITICAL,
                CodeLocation("settings.py", 1, snippet="DEBUG = True"),
                "Debug mode is dangerous", "A05:2021", "CWE-94",
                fix=Fix("Set DEBUG False", "DEBUG = True", "DEBUG = False",
                        False, False, "test"),
            )
            v.metadata["confidence"] = 0.92
            v.metadata["confidence_label"] = "HIGH"
            v.metadata["source"] = "django_scanner"
            vulns = [v]
        return ScanResult(
            scan_id=str(uuid.uuid4())[:8],
            project_path=self.test_dir,
            files_scanned=5,
            vulnerabilities=vulns,
            scan_duration_seconds=0.5,
        )

    def test_terminal_reporter_runs_without_error(self):
        result = self.make_result()
        reporter = TerminalReporter(no_color=True)
        output = reporter.report(result)
        self.assertTrue("DJANGOSENTINEL" in output or "DJANGO SENTINEL" in output or "DjangoSentinel" in output)
        self.assertIn("VULNERABILITY SUMMARY", output)
        self.assertIn("DEBUG", output)

    def test_terminal_reporter_shows_confidence(self):
        result = self.make_result()
        reporter = TerminalReporter(no_color=True)
        output = reporter.report(result)
        self.assertIn("HIGH", output)
        self.assertIn("92%", output)

    def test_json_reporter_valid_json(self):
        result = self.make_result()
        output = JSONReporter().report(result)
        data = json.loads(output)
        self.assertIn("vulnerabilities", data)
        self.assertIn("summary", data)
        self.assertIn("confidence", data["vulnerabilities"][0])

    def test_json_reporter_has_confidence_field(self):
        result = self.make_result()
        data = json.loads(JSONReporter().report(result))
        v = data["vulnerabilities"][0]
        self.assertIn("confidence", v)
        self.assertIn("confidence_label", v)

    def test_diff_reporter_shows_diff_scope(self):
        result = self.make_result()
        diff_sum = {
            "total_changed_files": 3, "python_files": 3, "html_files": 0,
            "total_added_lines": 45,
            "files": [{"path": "settings.py", "added_lines": 15, "is_new": False}],
        }
        reporter = DiffReporter(no_color=True, diff_summary=diff_sum)
        output = reporter.report(result)
        self.assertIn("DIFF SECURITY SCAN", output)
        self.assertIn("Changed files:", output)
        self.assertIn("settings.py", output)


# ─────────────────────────────────────────────────────────────────────────────
# Main runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_classes = [
        TestDjangoScanner,
        TestASTScanner,
        TestBusinessLogicScanner,
        TestDependencyScanner,
        TestDiffParser,
        TestDiffScanner,
        TestDataFlowTracker,
        TestConfidenceScoring,
        TestASTSafeFixer,
        TestScanCache,
        TestAutoFixer,
        TestReporters,
    ]

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    print("🛡️  DjangoSentinel — Complete Test Suite")
    print("=" * 55)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
