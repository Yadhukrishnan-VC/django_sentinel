# Contributing to DjangoSentinel

Thank you for helping make Django applications more secure! 🛡️

## Ways to Contribute

- **Add new vulnerability detections** — see `djangosentinel/scanners/`
- **Expand the CVE database** — see `VULN_DATABASE` in `dependency_scanner.py`
- **Write tests** — see `tests/test_all.py`
- **Improve auto-fixes** — see `djangosentinel/fixers/auto_fixer.py`
- **Report false positives or missed vulnerabilities** — open an issue

## Development Setup

```bash
git clone https://github.com/yourusername/django-sentinel
cd django-sentinel
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests
python tests/test_all.py

# With pytest (verbose)
pytest tests/ -v

# With coverage
pytest tests/ --cov=djangosentinel --cov-report=term-missing
```

## Adding a New Vulnerability Detection

### 1. Choose the right scanner

| Scanner | Use for |
|---------|---------|
| `DjangoScanner` | Django framework misuse, settings, views, templates |
| `BusinessLogicScanner` | Application-level logic flaws, financial ops, workflows |
| `DependencyScanner` | Known CVEs in third-party packages |

### 2. Add detection logic

```python
# In the appropriate scanner's scan() method:
def _scan_my_vuln(self, source: str, file_path: str):
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        if re.search(r'my_pattern', line):
            self.vulnerabilities.append(Vulnerability(
                vuln_id=str(uuid.uuid4())[:8],
                title="My Vulnerability Title",
                category=VulnCategory.INJECTION,      # Pick appropriate category
                severity=Severity.HIGH,
                location=CodeLocation(file_path, i, snippet=line.strip()),
                description="Clear description of what this is and why it's dangerous.",
                owasp_ref="A03:2021 – Injection",
                cwe_id="CWE-89",
                fix=Fix(
                    description="Short description of the fix",
                    original_code="dangerous_pattern()",
                    fixed_code="safe_alternative()",
                    explanation="Why the fix works.",
                    manual_review_required=False,  # True if context-dependent
                ),
            ))
```

### 3. Write tests

```python
def test_detects_my_vuln(self):
    self.write_file("views.py", "dangerous_pattern()\n")
    vulns = self.scan()
    self.assertTrue(any("My Vulnerability" in v.title for v in vulns))

def test_no_false_positive_my_vuln(self):
    self.write_file("views.py", "safe_alternative()\n")
    vulns = self.scan()
    self.assertFalse(any("My Vulnerability" in v.title for v in vulns))
```

### 4. Add to CVE database (for dependency issues)

```python
# In dependency_scanner.py VULN_DATABASE:
"my-package": [
    {
        "affected_below": "2.0.0",
        "affected_above": "0.0.0",
        "fixed": "2.0.0",
        "cve": "CVE-2024-XXXXX",
        "severity": Severity.HIGH,
        "title": "My Package Vulnerability Title",
        "description": "What the vulnerability is and its impact.",
    },
],
```

## Code Style

- Follow PEP 8
- Max line length: 100 characters
- Use `black` for formatting: `black djangosentinel/`
- Use `ruff` for linting: `ruff check djangosentinel/`

## Pull Request Checklist

- [ ] Tests pass: `python tests/test_all.py`
- [ ] New detections have corresponding tests
- [ ] False positive tests included
- [ ] No false positives on clean code
- [ ] Severity and OWASP reference are accurate
- [ ] Fix code is correct and safe to apply
- [ ] `manual_review_required=True` if fix is context-dependent

## Vulnerability Severity Guide

| Severity | When to use |
|----------|-------------|
| CRITICAL | Remote code execution, authentication bypass, direct data exfiltration |
| HIGH | Significant data exposure, privilege escalation, CSRF, most injections |
| MEDIUM | Information disclosure, SSRF, indirect exploitation |
| LOW | Defense-in-depth issues, best practice violations |
| INFO | Informational findings, coding style security notes |

## False Positive Policy

We take false positives seriously — they erode trust in the tool.

- If a detection generates >5% false positives in real Django projects, it should be made opt-in
- Always include a "no false positive" test for safe usage patterns
- Use context window lookups (lines around the match) to reduce false positives
