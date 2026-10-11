"""Regression tests for the AI engine, provider layer and secret auto-fix.

These tests use a fake provider, so they never call a real AI service.
"""
import json

from djangosentinel.models import (
    CodeLocation, ScanResult, Severity, VulnCategory, Vulnerability,
)
from djangosentinel import ai_engine
from djangosentinel.ai_engine import (
    AIExplainer, AIFixEngine, AIPatternScanner, PRReviewSummarizer,
)
from djangosentinel.scanners.django_scanner import DjangoScanner


class FakeProvider:
    """Stands in for a real AI provider."""

    def __init__(self, reply=None, available=True):
        self.reply = reply
        self.available = available
        self.calls = []

    def generate(self, system, user, max_tokens=1500, timeout=30):
        self.calls.append((system, user))
        return self.reply


def _vuln(title="Use of eval()"):
    return Vulnerability(
        vuln_id="t1", title=title, category=VulnCategory.INJECTION,
        severity=Severity.CRITICAL,
        location=CodeLocation("app/views.py", 7, snippet="eval(x)"),
        description="eval on user input", cwe_id="CWE-78",
    )


def _with(cls, provider):
    obj = cls()
    obj._provider = provider
    obj.available = provider.available
    return obj


class TestAIEngineImports:
    def test_all_public_classes_exist(self):
        # These names are exported by the package and imported by the CLI.
        for name in ("AIFixEngine", "AIExplainer", "AIPatternScanner", "PRReviewSummarizer"):
            assert hasattr(ai_engine, name)

    def test_cli_imports_work(self):
        from djangosentinel import cli  # noqa: F401
        from djangosentinel.ai_engine import AIFixEngine, AIExplainer, AIPatternScanner  # noqa: F401
        from djangosentinel.ai_engine import PRReviewSummarizer  # noqa: F401


class TestAIWithoutKey:
    def test_everything_degrades_gracefully(self, monkeypatch):
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        assert AIFixEngine().generate_fix(_vuln()) is None
        assert AIExplainer().explain(_vuln()) is None
        assert AIPatternScanner().scan_file("app/views.py", "import django\n" * 10) == []

    def test_pr_comment_falls_back_to_template(self, monkeypatch):
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        result = ScanResult("s1", "/tmp/p", 3, [_vuln()])
        text = PRReviewSummarizer().generate_pr_comment(result)
        assert "DjangoSentinel" in text


class TestAIWithFakeProvider:
    def test_explainer_returns_provider_text(self):
        engine = _with(AIExplainer, FakeProvider("  It is dangerous.  "))
        assert engine.explain(_vuln()) == "It is dangerous."

    def test_pattern_scanner_parses_json(self):
        reply = json.dumps({"vulnerabilities": [{
            "title": "Missing auth check", "severity": "HIGH", "cwe": "CWE-862",
            "line_hint": 4, "description": "No permission check",
            "fix_hint": "Add @login_required",
        }]})
        scanner = _with(AIPatternScanner, FakeProvider(reply))
        src = "from django.http import HttpResponse\n" + "x = 1\n" * 8
        found = scanner.scan_file("app/views.py", src)
        assert len(found) == 1
        assert found[0].title.startswith("[AI]")
        assert found[0].severity == Severity.HIGH
        assert found[0].fix.manual_review_required is True

    def test_pattern_scanner_ignores_bad_json(self):
        scanner = _with(AIPatternScanner, FakeProvider("not json"))
        src = "from django.http import HttpResponse\n" + "x = 1\n" * 8
        assert scanner.scan_file("app/views.py", src) == []

    def test_pattern_scanner_skips_boring_files(self):
        provider = FakeProvider("{}")
        scanner = _with(AIPatternScanner, provider)
        assert scanner.scan_file("app/migrations/0001.py", "import django\n" * 10) == []
        assert provider.calls == []

    def test_pr_comment_uses_ai_text(self):
        summ = _with(PRReviewSummarizer, FakeProvider("All good overall."))
        result = ScanResult("s1", "/tmp/p", 3, [_vuln()])
        assert "All good overall." in summ.generate_pr_comment(result)


class TestSecretFix:
    def test_fix_keeps_variable_name(self):
        fix = DjangoScanner._secret_fix('SECRET_KEY = "abcdefghijklmnop"')
        assert 'SECRET_KEY = os.environ["SECRET_KEY"]' in fix.fixed_code
        assert not fix.manual_review_required

    def test_fix_without_assignment_needs_manual_review(self):
        fix = DjangoScanner._secret_fix('headers = {"x": "Bearer abcdefghijklmnopqrstuv"}')
        assert fix.manual_review_required is True
        assert fix.fixed_code == ""
