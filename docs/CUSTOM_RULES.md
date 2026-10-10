# Writing Custom Detection Rules

DjangoSentinel is built to be extended. This guide covers:
1. Adding regex-based rules to existing scanners
2. Creating a standalone custom scanner
3. Adding AST-based detections
4. Extending the CVE database
5. Adding rules to the diff scanner
6. Testing your rules

---

## Quick Example (2 minutes)

Add this to `djangosentinel/scanners/django_scanner.py` inside `_scan_dangerous_functions()`:

```python
# Detect use of a project-specific deprecated function
if re.search(r'\blegacy_auth\s*\(', line):
    self.vulnerabilities.append(Vulnerability(
        vuln_id=str(uuid.uuid4())[:8],
        title="Deprecated Authentication Function Used",
        category=VulnCategory.AUTH,
        severity=Severity.HIGH,
        location=CodeLocation(file_path, i, snippet=line.strip()),
        description=(
            "legacy_auth() was deprecated in v2.0 and contains a known timing "
            "vulnerability. Use authenticate() from django.contrib.auth instead."
        ),
        owasp_ref="A07:2021 – Identification and Authentication Failures",
        cwe_id="CWE-287",
        fix=Fix(
            description="Replace legacy_auth() with django.contrib.auth.authenticate()",
            original_code="legacy_auth(username, password)",
            fixed_code=(
                "from django.contrib.auth import authenticate\n"
                "user = authenticate(request, username=username, password=password)"
            ),
            explanation="authenticate() uses Django's full auth backend pipeline.",
        ),
    ))
```

---

## Standalone Custom Scanner (Recommended for project-specific rules)

```python
# my_project/security/custom_scanner.py

import re
import uuid
from pathlib import Path
from typing import List

from djangosentinel.models import (
    Vulnerability, VulnCategory, Severity, CodeLocation, Fix
)


class MyProjectScanner:
    """
    Custom security rules for MyProject.
    """

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.vulnerabilities: List[Vulnerability] = []

    def scan(self) -> List[Vulnerability]:
        self.vulnerabilities = []

        for py_file in self.project_path.rglob("*.py"):
            if self._excluded(py_file):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                rel = str(py_file.relative_to(self.project_path))
                self._check_payment_skip(source, rel)
                self._check_internal_key_exposed(source, rel)
                self._check_hardcoded_user_ids(source, rel)
            except Exception:
                continue

        return self.vulnerabilities

    def _excluded(self, path: Path) -> bool:
        return any(p in path.parts for p in {"venv", ".venv", "__pycache__", ".git"})

    def _check_payment_skip(self, source: str, file_path: str):
        """Detect skip_payment debug flag left in code."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            if re.search(r'skip_payment\s*=\s*True', line, re.IGNORECASE):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Payment Skip Debug Flag Active",
                    category=VulnCategory.BUSINESS_LOGIC,
                    severity=Severity.CRITICAL,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "skip_payment=True bypasses the payment processing flow. "
                        "If this reaches production, users can receive goods without paying."
                    ),
                    owasp_ref="A04:2021 – Insecure Design",
                    cwe_id="CWE-841",
                    fix=Fix(
                        description="Remove skip_payment flag entirely",
                        original_code="skip_payment = True",
                        fixed_code="# Remove this flag — never use payment bypass in production",
                        explanation="Payment bypass flags must never exist in production code.",
                    ),
                ))

    def _check_internal_key_exposed(self, source: str, file_path: str):
        """Detect internal API key returned in HTTP responses."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            if re.search(r'INTERNAL_API_KEY.*response|JsonResponse.*INTERNAL_API', line):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Internal API Key Exposed in HTTP Response",
                    category=VulnCategory.SENSITIVE_DATA,
                    severity=Severity.CRITICAL,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description="INTERNAL_API_KEY is included in an HTTP response payload.",
                    owasp_ref="A02:2021 – Cryptographic Failures",
                    cwe_id="CWE-200",
                    fix=Fix(
                        description="Remove key from response",
                        original_code=line.strip(),
                        fixed_code="# Never return internal keys in HTTP responses",
                        manual_review_required=True,
                        explanation="Internal service keys must only be used server-side.",
                    ),
                ))

    def _check_hardcoded_user_ids(self, source: str, file_path: str):
        """Detect hardcoded user or admin IDs."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            if re.search(r'user_id\s*=\s*\d+|admin_id\s*=\s*\d+', line, re.IGNORECASE):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Hardcoded User ID in Source Code",
                    category=VulnCategory.MISCONFIG,
                    severity=Severity.MEDIUM,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "A user or admin ID is hardcoded. This breaks environment "
                        "separation and may expose a privileged account ID."
                    ),
                    owasp_ref="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-798",
                    fix=Fix(
                        description="Load from environment variable or settings",
                        original_code=line.strip(),
                        fixed_code="admin_id = settings.ADMIN_USER_ID  # set in env",
                        explanation="Never hardcode user IDs — use settings or env vars.",
                    ),
                ))
```

---

## Using Your Custom Scanner

```python
# run_scan.py
import uuid, time
from pathlib import Path
from djangosentinel.scanners import DjangoScanner, BusinessLogicScanner, ASTScanner
from djangosentinel.scanners.diff_scanner import DiffScanner, GitDiffSource
from djangosentinel.reporters import TerminalReporter, HTMLReporter
from djangosentinel.fixers import ContextAwareFixer
from djangosentinel.models import ScanResult
from my_project.security.custom_scanner import MyProjectScanner

PROJECT = "."

# Option A: Full scan
all_vulns = []
all_vulns.extend(DjangoScanner(PROJECT).scan())
all_vulns.extend(BusinessLogicScanner(PROJECT).scan())
all_vulns.extend(ASTScanner(PROJECT).scan())
all_vulns.extend(MyProjectScanner(PROJECT).scan())

# Option B: Diff scan (only changed lines)
diff_source = GitDiffSource(PROJECT)
diff_text = diff_source.get_diff(mode="staged")

diff_scanner = DiffScanner(PROJECT, diff_text)
all_vulns = diff_scanner.scan()
# Add custom scanner results, filtered to diff lines:
custom_vulns = MyProjectScanner(PROJECT).scan()
changed_lines = {
    f.path: set(f.all_added_lines.keys())
    for f in diff_scanner.diff_files
}
for v in custom_vulns:
    if v.location.file_path in changed_lines:
        if v.location.line_number in changed_lines[v.location.file_path]:
            all_vulns.append(v)

# Build result and report
result = ScanResult(
    scan_id=str(uuid.uuid4())[:8],
    project_path=PROJECT,
    files_scanned=len(list(Path(PROJECT).rglob("*.py"))),
    vulnerabilities=all_vulns,
    scan_duration_seconds=0.0,
)

print(TerminalReporter().report(result))
Path("report.html").write_text(HTMLReporter().report(result))
```

---

## AST-Based Custom Detection

For structural issues that regex cannot find, subclass or extend `_SecurityVisitor`:

```python
# my_project/security/ast_rules.py

import ast
import uuid
from djangosentinel.models import Vulnerability, VulnCategory, Severity, CodeLocation, Fix
from djangosentinel.scanners.ast_scanner import _SecurityVisitor


class ExtendedSecurityVisitor(_SecurityVisitor):
    """Adds project-specific AST checks to the base visitor."""

    def visit_Call(self, node: ast.Call):
        # Call parent checks first
        super().visit_Call(node)
        # Add custom checks
        self._check_unvalidated_json_loads(node)

    def _check_unvalidated_json_loads(self, node: ast.Call):
        """Detect json.loads() without try/except (unvalidated external data)."""
        call_name = self._get_call_name(node)
        if call_name != "json.loads":
            return

        # Check if this call is inside a try block
        # (simplified check — look at function name for context)
        fn_name = getattr(self, '_current_function', '') or ''
        external_terms = {"webhook", "external", "api", "receive", "parse"}
        if not any(t in fn_name.lower() for t in external_terms):
            return

        self._add(
            node,
            "json.loads() Without Validation on External Data",
            VulnCategory.INJECTION,
            Severity.MEDIUM,
            (
                "json.loads() raises ValueError on malformed input. In functions "
                "handling external/webhook data, unhandled exceptions may cause DoS "
                "or reveal stack traces."
            ),
            "A03:2021 – Injection",
            "CWE-20",
            Fix(
                description="Wrap json.loads() in try/except",
                original_code=self._snippet(node),
                fixed_code=(
                    "try:\n"
                    "    data = json.loads(raw)\n"
                    "except (json.JSONDecodeError, ValueError) as e:\n"
                    "    logger.warning('Invalid JSON received: %s', e)\n"
                    "    return HttpResponseBadRequest('Invalid JSON')"
                ),
                explanation="Always validate/catch JSON parsing errors from external sources.",
            ),
        )
```

---

## Extending the CVE Database

Add to `VULN_DATABASE` in `djangosentinel/scanners/dependency_scanner.py`:

```python
"my-internal-lib": [
    {
        "affected_below": "3.0.0",
        "affected_above": "0.0.0",
        "fixed": "3.0.0",
        "cve": "INTERNAL-2024-001",  # Use your internal ID if not public
        "severity": Severity.CRITICAL,
        "title": "my-internal-lib RCE in deserialize()",
        "description": (
            "Versions before 3.0.0 contain a remote code execution vulnerability "
            "in deserialize() when processing untrusted data."
        ),
    },
],
```

---

## Testing Your Rules

Always write both detection and false-positive tests:

```python
# tests/test_custom.py
import tempfile, shutil, unittest
from pathlib import Path
from my_project.security.custom_scanner import MyProjectScanner


class TestMyProjectScanner(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def write(self, name: str, content: str) -> Path:
        p = Path(self.test_dir) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return p

    def scan(self):
        return MyProjectScanner(self.test_dir).scan()

    # ── Detection tests ──────────────────────────────────────────────────────

    def test_detects_payment_skip(self):
        self.write("views.py", "skip_payment = True\n")
        vulns = self.scan()
        self.assertTrue(any("Payment Skip" in v.title for v in vulns))

    def test_detects_internal_key_in_response(self):
        self.write("views.py",
            "return JsonResponse({'key': INTERNAL_API_KEY, 'data': data})\n"
        )
        vulns = self.scan()
        self.assertTrue(any("Internal API Key" in v.title for v in vulns))

    def test_detects_hardcoded_user_id(self):
        self.write("utils.py", "admin_id = 42\n")
        vulns = self.scan()
        self.assertTrue(any("Hardcoded User ID" in v.title for v in vulns))

    # ── False positive tests ─────────────────────────────────────────────────

    def test_no_false_positive_payment_skip_false(self):
        self.write("views.py", "skip_payment = False\n")
        vulns = self.scan()
        self.assertFalse(any("Payment Skip" in v.title for v in vulns))

    def test_no_false_positive_payment_skip_comment(self):
        self.write("views.py", "# skip_payment = True\n")
        vulns = self.scan()
        self.assertFalse(any("Payment Skip" in v.title for v in vulns))

    def test_no_false_positive_user_id_dynamic(self):
        self.write("utils.py", "user_id = request.user.pk\n")
        vulns = self.scan()
        self.assertFalse(any("Hardcoded User ID" in v.title for v in vulns))


if __name__ == "__main__":
    unittest.main(verbosity=2)
```

---

## Severity Selection Guide

| Finding | Assign |
|---------|--------|
| Unauthenticated RCE or full account takeover | CRITICAL |
| Significant privilege escalation or mass data theft | HIGH |
| Information disclosure, indirect exploitation, SSRF | MEDIUM |
| Best practice violation, defence-in-depth | LOW |
| Purely informational, no direct exploitability | INFO |

## auto_fix vs manual_review_required

| Situation | Setting |
|-----------|---------|
| Fix is a one-line deterministic swap | `manual_review_required=False` |
| Fix needs understanding the full function | `manual_review_required=True` |
| Fix is a placeholder hint only | `manual_review_required=True` |
| Multiple valid fixes depending on context | `manual_review_required=True` |

## PR Checklist Before Submitting a New Detection

- [ ] Detection test passes
- [ ] False-positive test on safe code passes
- [ ] Severity matches the guide above
- [ ] OWASP ref and CWE ID are accurate
- [ ] `fix.explanation` explains WHY in plain language
- [ ] `manual_review_required` set correctly
- [ ] No false positives on existing DjangoSentinel source code
