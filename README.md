# 🛡️ DjangoSentinel

**Enterprise AI Security Assistant for Python/Django**  
*Finds and auto-fixes vulnerabilities before they reach production.*

[![CI](https://github.com/yourusername/django-sentinel/actions/workflows/security.yml/badge.svg)](https://github.com/yourusername/django-sentinel/actions)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What It Detects

DjangoSentinel runs three specialized scanners on your codebase:

### 🔧 Django-Specific Vulnerabilities
| Vulnerability | Severity | Auto-Fix |
|---|---|---|
| `DEBUG=True` in production | 🔴 CRITICAL | ✅ |
| Weak / default `SECRET_KEY` | 🔴 CRITICAL | — |
| `ALLOWED_HOSTS = ['*']` wildcard | 🟠 HIGH | — |
| CSRF middleware missing | 🟠 HIGH | — |
| Session cookies transmitted over HTTP | 🟠 HIGH | ✅ |
| CORS allowing all origins | 🟠 HIGH | ✅ |
| SQL injection via string formatting | 🔴 CRITICAL | ⚠️ Manual |
| Server-Side Template Injection (SSTI) | 🔴 CRITICAL | ⚠️ Manual |
| XSS via `mark_safe()` with user input | 🔴 CRITICAL | ⚠️ Manual |
| `@csrf_exempt` on sensitive views | 🟠 HIGH | ⚠️ Manual |
| Open redirect from user input | 🟡 MEDIUM | ✅ |
| Mass assignment via `fields='__all__'` | 🟠 HIGH | ✅ |
| IDOR (object access without auth check) | 🟠 HIGH | ⚠️ Manual |
| `subprocess` with `shell=True` | 🔴 CRITICAL | ✅ |
| `eval()` / `exec()` usage | 🔴 CRITICAL | ⚠️ Manual |
| `pickle.loads()` unsafe deserialization | 🔴 CRITICAL | ⚠️ Manual |
| MD5 password hasher | 🔴 CRITICAL | — |
| Missing HSTS configuration | 🟡 MEDIUM | ✅ |
| Clickjacking protection disabled | 🟡 MEDIUM | ✅ |
| XSS via `{% autoescape off %}` | 🟠 HIGH | ✅ |
| Hardcoded passwords / API keys / secrets | 🔴 CRITICAL | ✅ |

### 🧠 Business Logic Vulnerabilities
| Vulnerability | Severity | Auto-Fix |
|---|---|---|
| Race condition in balance/inventory check | 🟠 HIGH | ✅ |
| Floating-point arithmetic for money | 🟡 MEDIUM | ✅ |
| Negative quantity/price not validated | 🟠 HIGH | ✅ |
| Privilege escalation via user-controlled role | 🔴 CRITICAL | ⚠️ Manual |
| Workflow bypass (order status skip) | 🟠 HIGH | ⚠️ Manual |
| Coupon/promo code reuse per user | 🟡 MEDIUM | ✅ |
| Paginated queryset exposes all users' data | 🟡 MEDIUM | ⚠️ Manual |
| Timezone-naive datetime for token expiry | 🟡 MEDIUM | ✅ |
| Missing negative balance guard | 🟠 HIGH | ✅ |

### 📦 Vulnerable Dependencies (CVE Database)
Checks `requirements.txt`, `Pipfile`, `pyproject.toml` against known CVEs:

- **Django** — path traversal, DoS, timing attacks
- **Pillow** — decompression bombs, DoS
- **PyYAML** — unsafe deserialization (RCE)
- **requests** — header leakage on redirect
- **celery** — RCE via pickle serialization
- **cryptography** — SSH protocol attacks
- **Jinja2** — XSS in xmlattr filter
- **Werkzeug** — multipart DoS
- **urllib3** — cookie header leakage
- **paramiko** — Terrapin attack
- And more...

---

## Installation

```bash
# From PyPI (when published)
pip install django-sentinel

# From source
git clone https://github.com/yourusername/django-sentinel
cd django-sentinel
pip install -e .
```

---

## Quick Start

```bash
# Scan your Django project
sentinel scan /path/to/your/project

# Scan and auto-fix safe vulnerabilities
sentinel scan . --fix

# Generate HTML report
sentinel scan . --format html -o security-report.html

# Generate SARIF (for GitHub Code Scanning)
sentinel scan . --format sarif -o results.sarif

# Block CI on CRITICAL vulnerabilities
sentinel scan . --fail-on critical

# Preview what would be fixed (no changes applied)
sentinel fix . --dry-run
```

---

## Git Hooks — Block Vulnerabilities Before Commit/Push

```bash
# Install pre-commit and pre-push hooks
sentinel install-hooks

# Check hook status
sentinel hook-status

# Uninstall hooks
sentinel uninstall-hooks
```

After installation:
- **Pre-commit hook**: Scans staged `.py` and `.html` files. Blocks commit on CRITICAL vulnerabilities.
- **Pre-push hook**: Full project scan. Blocks push on HIGH+ vulnerabilities.

---

## GitHub Actions Integration

Add to `.github/workflows/security.yml`:

```yaml
- name: Install DjangoSentinel
  run: pip install django-sentinel

- name: Security Scan
  run: sentinel scan . --format sarif -o results.sarif

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

This integrates with GitHub's Security tab and shows findings inline in pull requests.

---

## Output Formats

| Format | Use Case |
|---|---|
| `terminal` | Developer workflow, CI logs |
| `json` | API integration, custom tooling |
| `html` | Security reports, stakeholder review |
| `sarif` | GitHub Code Scanning, VS Code |

---

## Auto-Fix Engine

DjangoSentinel's fixer applies safe, deterministic fixes:

```bash
sentinel scan . --fix           # Auto-fix + scan
sentinel fix . --dry-run        # Preview without applying
sentinel fix . --no-backup      # Skip backup creation (not recommended)
```

**Before modifying any file**, DjangoSentinel creates timestamped backups in `.sentinel_backups/`.

Issues marked ⚠️ **require manual review** because the safe fix depends on application context.

---

## Project Structure

```
django-sentinel/
├── djangosentinel/
│   ├── models.py              # Vulnerability data models
│   ├── cli.py                 # CLI entry point
│   ├── scanners/
│   │   ├── django_scanner.py  # Django-specific scanner
│   │   ├── business_logic_scanner.py  # Logic flaw scanner
│   │   └── dependency_scanner.py      # CVE dependency scanner
│   ├── fixers/
│   │   └── auto_fixer.py      # Automated fix engine
│   ├── reporters/
│   │   └── reporters.py       # Terminal/JSON/HTML/SARIF output
│   └── hooks/
│       └── git_hooks.py       # Pre-commit/pre-push installers
├── tests/
│   └── test_all.py            # Comprehensive test suite
├── examples/
│   └── vulnerable_app/        # Demo app with intentional vulns
├── .github/
│   └── workflows/
│       └── security.yml       # GitHub Actions CI
└── setup.py
```

---

## Extending DjangoSentinel

Add custom rules by creating a scanner class:

```python
from djangosentinel.models import Vulnerability, VulnCategory, Severity, CodeLocation, Fix

class MyCustomScanner:
    def __init__(self, project_path: str):
        self.project_path = project_path

    def scan(self) -> list[Vulnerability]:
        # Your scanning logic
        return []
```

Then integrate with the CLI or use programmatically:

```python
from djangosentinel.scanners import DjangoScanner, BusinessLogicScanner
from djangosentinel.reporters import TerminalReporter
from djangosentinel.models import ScanResult

scanner = DjangoScanner("/path/to/project")
vulns = scanner.scan()
result = ScanResult(scan_id="...", project_path="...", files_scanned=10, vulnerabilities=vulns)
print(TerminalReporter().report(result))
```

---

## Running Tests

```bash
python tests/test_all.py
```

---

## OWASP Coverage

| OWASP Top 10 (2021) | Coverage |
|---|---|
| A01 – Broken Access Control | ✅ IDOR, CSRF, mass assignment, privilege escalation |
| A02 – Cryptographic Failures | ✅ Weak secrets, MD5, insecure cookies |
| A03 – Injection | ✅ SQL injection, SSTI, command injection, XSS |
| A04 – Insecure Design | ✅ Race conditions, business logic flaws |
| A05 – Security Misconfiguration | ✅ DEBUG, CORS, HSTS, clickjacking |
| A06 – Vulnerable Components | ✅ CVE database for 12+ packages |
| A07 – Auth Failures | ✅ Session security, token expiry |

---

## License

MIT License — See [LICENSE](LICENSE)

---

## ⚠️ Disclaimer

DjangoSentinel is a static analysis tool. It finds many common vulnerabilities but cannot guarantee 100% coverage. Always combine with manual security review, penetration testing, and secure development practices.
