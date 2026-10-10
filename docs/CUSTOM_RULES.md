# Writing Custom Detection Rules

DjangoSentinel is designed to be extended. This guide walks through adding
your own vulnerability detections for project-specific security requirements.

---

## Quick Example

Add this to `djangosentinel/scanners/django_scanner.py` inside `_scan_views()`:

```python
# Detect use of a deprecated/insecure internal function
if re.search(r'legacy_auth\(', line):
    self.vulnerabilities.append(Vulnerability(
        vuln_id=str(uuid.uuid4())[:8],
        title="Deprecated Authentication Function Used",
        category=VulnCategory.AUTH,
        severity=Severity.HIGH,
        location=CodeLocation(file_path, i, snippet=line.strip()),
        description=(
            "legacy_auth() was deprecated in v2.0 and contains a known "
            "timing vulnerability. Replace with authenticate() from django.contrib.auth."
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

## Standalone Custom Scanner

For project-specific rules that don't belong in the core, create your own scanner class:

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
    Detects project-specific anti-patterns.
    """

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.vulnerabilities: List[Vulnerability] = []

    def scan(self) -> List[Vulnerability]:
        self.vulnerabilities = []
        for py_file in self.project_path.rglob("*.py"):
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(py_file.relative_to(self.project_path))
                self._check_internal_api_key_exposure(source, rel_path)
                self._check_skip_payment_flag(source, rel_path)
            except Exception:
                continue
        return self.vulnerabilities

    def _check_internal_api_key_exposure(self, source: str, file_path: str):
        """Detect exposure of internal API key in responses."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            if re.search(r'INTERNAL_API_KEY.*response|JsonResponse.*INTERNAL', line):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Internal API Key Exposed in HTTP Response",
                    category=VulnCategory.SENSITIVE_DATA,
                    severity=Severity.CRITICAL,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "An internal API key appears to be included in an HTTP response. "
                        "This exposes the key to any client that can make requests."
                    ),
                    owasp_ref="A02:2021 – Cryptographic Failures",
                    cwe_id="CWE-200",
                    fix=Fix(
                        description="Remove INTERNAL_API_KEY from response payload",
                        original_code=line.strip(),
                        fixed_code="# Remove key from response; use server-side-only calls",
                        manual_review_required=True,
                        explanation="Internal keys must never appear in HTTP responses.",
                    ),
                ))

    def _check_skip_payment_flag(self, source: str, file_path: str):
        """Detect skip_payment debug flag left in production code."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            if re.search(r'skip_payment\s*=\s*True|SKIP_PAYMENT\s*=\s*True', line):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Payment Skip Debug Flag Enabled",
                    category=VulnCategory.BUSINESS_LOGIC,
                    severity=Severity.CRITICAL,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "A skip_payment=True flag is present. If this reaches production, "
                        "users may be able to bypass payment processing entirely."
                    ),
                    owasp_ref="A04:2021 – Insecure Design",
                    cwe_id="CWE-841",
                    fix=Fix(
                        description="Remove skip_payment flag",
                        original_code="skip_payment = True",
                        fixed_code="# Remove this flag entirely",
                        explanation="Payment bypass flags must never exist in production code.",
                    ),
                ))
```

---

## Integrating Custom Scanners with the CLI

You can run your custom scanner alongside the built-in ones:

```python
# run_scan.py
from pathlib import Path
from djangosentinel.scanners import DjangoScanner, BusinessLogicScanner
from djangosentinel.reporters import TerminalReporter, HTMLReporter
from djangosentinel.fixers import AutoFixer
from djangosentinel.models import ScanResult
from my_project.security.custom_scanner import MyProjectScanner
import uuid, time

PROJECT = "."

all_vulns = []
start = time.time()

all_vulns.extend(DjangoScanner(PROJECT).scan())
all_vulns.extend(BusinessLogicScanner(PROJECT).scan())
all_vulns.extend(MyProjectScanner(PROJECT).scan())

result = ScanResult(
    scan_id=str(uuid.uuid4())[:12],
    project_path=PROJECT,
    files_scanned=sum(1 for _ in Path(PROJECT).rglob("*.py")),
    vulnerabilities=all_vulns,
    scan_duration_seconds=time.time() - start,
)

# Print to terminal
print(TerminalReporter().report(result))

# Save HTML report
Path("security-report.html").write_text(HTMLReporter().report(result))
```

---

## Adding CVEs to the Dependency Database

Open `djangosentinel/scanners/dependency_scanner.py` and add to `VULN_DATABASE`:

```python
"my-internal-lib": [
    {
        "affected_below": "3.0.0",
        "affected_above": "0.0.0",
        "fixed": "3.0.0",
        "cve": "INTERNAL-2024-001",        # Use your internal ID if not public
        "severity": Severity.CRITICAL,
        "title": "My Internal Lib RCE in deserialize()",
        "description": (
            "Versions before 3.0.0 of my-internal-lib contain a remote code "
            "execution vulnerability in the deserialize() function when processing "
            "untrusted data."
        ),
    },
],
```

---

## Severity Selection Guide

| Your finding... | Assign |
|---|---|
| Allows unauthenticated RCE or full account takeover | CRITICAL |
| Allows significant privilege escalation or data theft | HIGH |
| Leaks information, indirect exploitation, SSRF | MEDIUM |
| Best practice violation, defense-in-depth issue | LOW |
| Purely informational, no direct exploitability | INFO |

---

## Testing Your Custom Rules

Always write tests before opening a PR or shipping custom rules:

```python
import tempfile, shutil, unittest
from pathlib import Path
from my_project.security.custom_scanner import MyProjectScanner

class TestMyScanner(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def write(self, name, content):
        p = Path(self.test_dir) / name
        p.write_text(content)

    def scan(self):
        return MyProjectScanner(self.test_dir).scan()

    def test_detects_payment_skip(self):
        self.write("views.py", "skip_payment = True\n")
        self.assertTrue(any("Payment Skip" in v.title for v in self.scan()))

    def test_no_false_positive_payment(self):
        self.write("views.py", "skip_payment = False\n")
        self.assertFalse(any("Payment Skip" in v.title for v in self.scan()))
```
