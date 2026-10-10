# 🛡️ DjangoSentinel

**Enterprise AI Security Scanner for Python / Django**

Finds and auto-fixes vulnerabilities **before production** — using a three-layer engine:

```
Rules (fast + free)   →  25+ Django-specific patterns, always-on
AST (structural)      →  Timing attacks, CBV auth gaps, unsafe defaults
AI (Claude)           →  Complex fixes, unknown patterns, PR summaries
```

---

## Feature Overview

| Feature | Command |
|---------|---------|
| Full project scan | `sentinel scan .` |
| **Git diff scan** (changed lines only) | `sentinel scan . --diff` |
| Staged-only scan (pre-commit) | `sentinel scan . --diff --staged` |
| PR scan vs branch | `sentinel scan . --diff --base main` |
| Rule-based auto-fix | `sentinel scan . --fix` |
| AI-assisted complex fixes | `sentinel scan . --fix --ai` |
| AI deep pattern scan | `sentinel scan . --ai-deep` |
| AI explanation of any line | `sentinel explain views.py 42` |
| HTML security dashboard | `sentinel scan . --format html -o r.html` |
| SARIF (GitHub Code Scanning) | `sentinel scan . --format sarif -o r.sarif` |
| GitHub PR comment + inline | `sentinel scan . --pr-comment --pr-inline` |
| GitHub Check Run (pass/fail) | `sentinel scan . --pr-check` |
| Git pre-commit/pre-push hooks | `sentinel install-hooks` |
| CI build gate | `sentinel scan . --fail-on high` |

---

## Installation

```bash
# From source
git clone https://github.com/yourusername/django-sentinel
cd django-sentinel
pip install -e .

# The sentinel command is now available in your venv
sentinel scan .
```

---

## Quick Start

### 1 — First scan
```bash
sentinel scan /your/django/project
```

### 2 — Scan only what changed (fastest, ideal for PR review)
```bash
# Everything changed since last commit
sentinel scan . --diff

# Only staged files (what you're about to commit)
sentinel scan . --diff --staged

# Changes vs a specific branch (PR simulation)
sentinel scan . --diff --base main

# Changes between two commits
sentinel scan . --diff --base abc1234 --head def5678

# Scan a saved .diff or .patch file
sentinel scan . --diff-file changes.patch
```

### 3 — Auto-fix
```bash
# Rule-based fixes (fast, free, safe)
sentinel scan . --fix

# Rule-based + AI fixes for complex multi-line issues
sentinel scan . --fix --ai

# Preview without touching files
sentinel scan . --fix --dry-run
```

### 4 — AI explanations
```bash
# Explain why line 42 in views.py is dangerous
sentinel explain views.py 42

# Add AI explanations to every finding in the scan
sentinel scan . --ai-explain

# Full AI deep scan (Claude reviews every file for unknown patterns)
sentinel scan . --ai-deep
```

### 5 — Install git hooks (one-time setup)
```bash
sentinel install-hooks
```
From now on, every `git commit` scans staged changes and every `git push` scans the full diff.

---

## Architecture — How It Works

```
sentinel scan . [--diff] [--fix] [--ai]
        │
        ▼
┌────────────────────────────────────────────────┐
│  LAYER 1 — RULE ENGINE (always runs, free)     │
│                                                │
│  DjangoScanner          regex on .py / .html  │
│  BusinessLogicScanner   context-aware patterns │
│  DependencyScanner      CVE database lookup    │
└──────────────────────┬─────────────────────────┘
                       │
┌──────────────────────▼─────────────────────────┐
│  LAYER 2 — AST ENGINE (structural analysis)    │
│                                                │
│  ASTScanner  walks Python parse tree:          │
│  • CBV missing LoginRequiredMixin              │
│  • Timing attacks in token comparisons         │
│  • Silent exception swallow in auth code       │
│  • Insecure random() for security values       │
│  • Dynamic getattr() with user input           │
│  • assert used as security gate                │
└──────────────────────┬─────────────────────────┘
                       │
┌──────────────────────▼─────────────────────────┐
│  LAYER 3 — AI ENGINE  (with --ai flag)         │
│  Uses Claude claude-sonnet-4-20250514          │
│                                                │
│  AIFixEngine       multi-line fix generation  │
│  AIExplainer       "why is this risky" prose   │
│  AIPatternScanner  unknown pattern detection   │
│  PRReviewSummarizer  GitHub PR comment AI      │
└──────────────────────┬─────────────────────────┘
                       │
┌──────────────────────▼─────────────────────────┐
│  DIFF FILTER  (with --diff flag)               │
│                                                │
│  DiffParser    parses unified diff format      │
│  DiffScanner   runs all scanners, then         │
│                filters to changed lines only   │
└──────────────────────┬─────────────────────────┘
                       │
┌──────────────────────▼─────────────────────────┐
│  FIX ENGINE                                    │
│                                                │
│  AutoFixer         simple deterministic fixes  │
│  ContextAwareFixer rule + AI, with backup      │
└──────────────────────┬─────────────────────────┘
                       │
┌──────────────────────▼─────────────────────────┐
│  REPORTERS                                     │
│                                                │
│  TerminalReporter    coloured grouped output   │
│  DiffReporter        diff-aware compact view   │
│  JSONReporter        machine-readable          │
│  HTMLReporter        browser dashboard         │
│  SARIFReporter       GitHub Code Scanning      │
└────────────────────────────────────────────────┘
```

---

## File Map — Every File Explained

```
django-sentinel/
│
├── djangosentinel/                   ← the Python package
│   ├── __init__.py                   sets version "1.0.0"
│   ├── __main__.py                   python -m djangosentinel scan .
│   ├── models.py                     Vulnerability, Fix, ScanResult data classes
│   ├── cli.py                        all CLI commands and orchestration
│   ├── ai_engine.py                  Claude API: fix, explain, pattern, PR summary
│   ├── github_integration.py         PR comments, inline annotations, Check Runs
│   │
│   ├── scanners/
│   │   ├── django_scanner.py         25+ regex-based Django vulnerability detections
│   │   ├── business_logic_scanner.py race conditions, float money, workflow bypass
│   │   ├── dependency_scanner.py     CVE database for 12 packages, dangerous imports
│   │   ├── ast_scanner.py            structural analysis: CBV, timing, assert misuse
│   │   └── diff_scanner.py           git diff parser + diff-scoped scanning
│   │
│   ├── fixers/
│   │   ├── auto_fixer.py             deterministic text replacement with backup
│   │   └── context_fixer.py         rule + AI fix pipeline, context extraction
│   │
│   ├── reporters/
│   │   └── reporters.py             Terminal, Diff, JSON, HTML, SARIF reporters
│   │
│   └── hooks/
│       └── git_hooks.py             pre-commit / pre-push script installer
│
├── tests/
│   └── test_all.py                  50 unit tests (34 scanner + 16 diff)
│
├── docs/
│   ├── OWASP_COVERAGE.md            A01–A10 coverage map
│   ├── CI_INTEGRATION.md            GitHub/GitLab/Jenkins/Bitbucket configs
│   └── CUSTOM_RULES.md              how to add your own detections
│
├── .github/workflows/
│   └── security.yml                 4-job CI: scan, test, AI deep, deps
│
├── .sentinel.yml                    project config (scanners, AI, CI, GitHub)
├── pyproject.toml                   packaging: name, version, entry points
├── setup.py                         legacy pip compatibility
├── .gitignore                       excludes venv, backups, secrets, outputs
├── LICENSE                          MIT
├── README.md                        this file
├── CHANGELOG.md                     version history
├── CONTRIBUTING.md                  how to add detections
└── SECURITY.md                      how to report tool vulnerabilities
```

---

## What It Detects — Full List

### Django Scanner (25+ patterns)

**Settings vulnerabilities**
- `DEBUG=True` in production → CRITICAL (auto-fixed)
- Weak/default `SECRET_KEY` → CRITICAL
- `ALLOWED_HOSTS=['*']` wildcard → HIGH
- Missing CSRF middleware → HIGH
- `SESSION_COOKIE_SECURE=False` → HIGH (auto-fixed)
- `CSRF_COOKIE_SECURE=False` → MEDIUM (auto-fixed)
- `CORS_ALLOW_ALL_ORIGINS=True` → HIGH (auto-fixed)
- `SECURE_HSTS_SECONDS=0` → MEDIUM (auto-fixed)
- `X_FRAME_OPTIONS=ALLOWALL` → MEDIUM (auto-fixed)
- `MD5PasswordHasher` → CRITICAL
- `SECURE_CONTENT_TYPE_NOSNIFF=False` → LOW (auto-fixed)

**View vulnerabilities**
- SQL injection via f-string/format → CRITICAL (manual review)
- Server-Side Template Injection via `Template(f"...")` → CRITICAL (manual review)
- XSS via `mark_safe()` with user input → CRITICAL (manual review)
- `@csrf_exempt` on sensitive views → HIGH (manual review)
- Open redirect from unvalidated user input → MEDIUM (auto-fixed)
- Mass assignment via `fields='__all__'` → HIGH (auto-fixed)
- IDOR — object lookup without ownership check → HIGH (manual review)

**Dangerous functions**
- `eval()` / `exec()` → CRITICAL (manual review)
- `pickle.loads()` → CRITICAL (manual review)
- `yaml.load()` without SafeLoader → HIGH (manual review)
- `subprocess` with `shell=True` → CRITICAL (auto-fixed)
- `os.system()` → HIGH (manual review)

**Secrets**
- Hardcoded passwords, API keys, AWS credentials, DB URLs, bearer tokens → CRITICAL (auto-fixed)

**Templates**
- `{% autoescape off %}` → HIGH (auto-fixed)
- `{{ var|safe }}` on user-controlled variables → HIGH (auto-fixed)

### AST Scanner (structural)

- CBV missing `LoginRequiredMixin` → MEDIUM (manual review)
- FBV missing `@login_required` on sensitive views → MEDIUM (manual review)
- `==` comparison of secrets/tokens (timing attack) → HIGH (auto-fixed)
- Silent `except: pass` in auth/security functions → HIGH (auto-fixed)
- `random.choice()` / `random.randint()` for security values → HIGH (auto-fixed)
- `hashlib.md5()` / `hashlib.sha1()` for secrets → HIGH (auto-fixed)
- `getattr(obj, user_input)` dynamic attribute access → HIGH (auto-fixed)
- `assert` used as security gate → HIGH (auto-fixed)
- Mutable default args in security functions → MEDIUM (auto-fixed)
- Log injection via f-string in logging calls → LOW (auto-fixed)
- Hardcoded private IP address → LOW (auto-fixed)
- `is True` comparison in permission checks → LOW (auto-fixed)

### Business Logic Scanner

- Race condition in balance/inventory check without `select_for_update` → HIGH (auto-fixed)
- `float()` for monetary values → MEDIUM (auto-fixed)
- Negative price/quantity not validated → HIGH (auto-fixed)
- Privilege escalation via user-controlled `is_staff`/`is_superuser` → CRITICAL (manual review)
- Workflow state bypass (order status skipped) → HIGH (manual review)
- Coupon/promo code reuse per user → MEDIUM (manual review)
- Paginated queryset without user filter → MEDIUM (manual review)
- `datetime.now()` for token expiry → MEDIUM (auto-fixed)
- Missing negative balance guard → HIGH (auto-fixed)

### Dependency Scanner (CVE database)

| Package | CVE | Severity |
|---------|-----|----------|
| Django (multiple) | CVE-2023-31047, CVE-2023-41164, CVE-2023-46695 | CRITICAL/HIGH |
| Pillow | CVE-2022-45199, CVE-2023-44271 | HIGH |
| PyYAML | CVE-2020-14343 | CRITICAL |
| celery | CVE-2021-23727 | HIGH |
| requests | CVE-2023-32681 | MEDIUM |
| cryptography | CVE-2023-38325 | HIGH |
| Jinja2 | CVE-2024-22195 | MEDIUM |
| Werkzeug | CVE-2023-46136 | HIGH |
| urllib3 | CVE-2023-43804 | MEDIUM |
| paramiko | CVE-2023-48795 | MEDIUM |
| SQLAlchemy | CVE-2019-7164 | HIGH |
| DRF | CVE-2023-28021 | HIGH |
| Dangerous imports | pickle, marshal, shelve, xmlrpc | HIGH |

---

## Diff Mode — In Depth

`--diff` is the most important mode for day-to-day use. It scans **only the lines you changed**, not the entire codebase. This makes it:

- **Fast** — sub-second on most PRs
- **Precise** — no noise from pre-existing issues  
- **PR-ready** — reports exactly what this change introduces

### How it works internally

```
git diff HEAD → unified diff text
       │
       ▼
DiffParser: parse unified diff into DiffFile objects
  Each DiffFile has:
    - path: "myapp/views.py"
    - hunks: [DiffHunk, DiffHunk, ...]
    - added_line_numbers: {14, 15, 16}  ← only ADDED lines
       │
       ▼
DiffScanner: for each changed file:
  1. Read FULL file content (AST needs full context)
  2. Run DjangoScanner, ASTScanner, BusinessLogicScanner
  3. Filter findings to added_line_numbers only
  4. Tag each finding with diff_detected=True
       │
       ▼
DiffReporter: grouped by file, shows:
  - Diff scope (files changed, lines added)
  - Only findings in the diff
  - Line numbers, snippets, fix hints
```

### Diff modes

```bash
sentinel scan . --diff                    # git diff HEAD (all local changes)
sentinel scan . --diff --staged           # git diff --staged (about to commit)
sentinel scan . --diff --base main        # changes vs main branch
sentinel scan . --diff --base origin/main # changes vs remote main
sentinel scan . --diff --base abc1234     # changes since a specific commit
sentinel scan . --diff --base abc --head def  # range between two commits
sentinel scan . --diff-file pr.patch      # scan a saved .patch file
```

---

## AI Engine — In Depth

Set your API key: `export ANTHROPIC_API_KEY=sk-ant-...`

### What AI does (and when)

| Situation | AI Role | Flag |
|-----------|---------|------|
| Vulnerability needs multi-line refactoring | Generates the fix | `--fix --ai` |
| Complex query rewrite needed | Generates parameterized version | `--fix --ai` |
| Developer wants to understand risk | Prose explanation in context | `--ai-explain` |
| Novel/unknown pattern | Pattern detection via reasoning | `--ai-deep` |
| GitHub PR needs a summary comment | Writes PR review in Markdown | `--pr-comment --ai` |

### What AI does NOT do

- Simple pattern detection (regex is faster and free)
- Basic one-line fixes (rule engine handles those)
- Anything where the fix is deterministic

### AI vs Rule comparison

```python
# DEBUG = True  →  Rule engine: instant, free, always correct
# Fix: "DEBUG = False"

# SQL injection in complex ORM call:
queryset = User.objects.raw(
    "SELECT * FROM auth_user WHERE username = %s" % username
)
# Fix needs to understand the full query context  →  AI engine generates:
queryset = User.objects.filter(username=username)
```

---

## GitHub PR Integration

### Setup (GitHub Actions — fully automated)

The included `.github/workflows/security.yml` does everything automatically:

1. **Runs on every PR** — scans the diff, not the whole project
2. **Posts inline annotations** — highlights the exact line in the diff view
3. **Posts a summary comment** — AI-generated (if key set) or template
4. **Creates a Check Run** — shows ✅/❌ on the PR
5. **Uploads SARIF** — findings appear in the Security tab

```yaml
# Already included in .github/workflows/security.yml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}  # auto-set by GitHub
  ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}  # add this secret
```

### Manual PR integration

```bash
# Post summary comment on PR #42
sentinel scan . --diff --base main \
  --pr-comment \
  --gh-repo owner/repo \
  --gh-pr 42 \
  --gh-token $GITHUB_TOKEN

# Full integration: comment + inline + check run + AI
sentinel scan . --diff --base main \
  --pr-comment --pr-inline --pr-check \
  --ai \
  --gh-repo owner/repo --gh-pr 42

# Update existing comment (auto-detects previous sentinel comment)
sentinel scan . --pr-comment  # posts new or updates existing
```

---

## Configuration — `.sentinel.yml`

Place at project root. All settings are optional — DjangoSentinel works without this file.

```yaml
# .sentinel.yml

scan:
  exclude_dirs: ["venv", ".venv", "legacy"]
  scanners:
    django: true
    ast: true
    business_logic: true
    dependencies: true

ai:
  enabled: false        # true = always use AI without --ai flag
  deep_scan: false      # true = always deep scan without --ai-deep flag
  explain: false        # true = always explain without --ai-explain flag

fix:
  backup: true
  auto_fix_level: "high"

ci:
  fail_on: "critical"
  sarif_output: "sentinel-results.sarif"

github:
  pr_comment: false
  pr_inline: false
  pr_check: false

hooks:
  pre_commit_fail_on: "critical"
  pre_push_fail_on: "high"

ignore:
  - file: "webhooks/views.py"
    line: 28
    title_contains: "CSRF"
    reason: "Uses HMAC webhook signature verification"
```

---

## Complete Command Reference

```bash
# ── FULL SCAN ─────────────────────────────────────────────────────────────
sentinel scan .                           # all files, terminal output
sentinel scan . --no-color                # no ANSI colours (for CI logs)
sentinel scan . --skip-deps               # skip CVE dependency check
sentinel scan . --skip-logic              # skip business logic scan
sentinel scan . --skip-ast                # skip AST structural scan

# ── DIFF SCAN (changed lines only) ────────────────────────────────────────
sentinel scan . --diff                    # vs HEAD (all local changes)
sentinel scan . --diff --staged           # staged changes only
sentinel scan . --diff --base main        # vs main branch
sentinel scan . --diff --base origin/main # vs remote branch
sentinel scan . --diff --base abc1234     # vs specific commit
sentinel scan . --diff --base a --head b  # range between commits
sentinel scan . --diff-file patch.diff    # from a saved diff file

# ── REPORTS ───────────────────────────────────────────────────────────────
sentinel scan . --format terminal         # coloured terminal (default)
sentinel scan . --format json -o r.json   # machine-readable JSON
sentinel scan . --format html -o r.html   # browser dashboard
sentinel scan . --format sarif -o r.sarif # GitHub Code Scanning

# ── FIXING ────────────────────────────────────────────────────────────────
sentinel scan . --fix                     # rule-based auto-fix
sentinel scan . --fix --ai               # rule + AI complex fixes
sentinel scan . --fix --dry-run           # preview without applying
sentinel fix .                            # fix only (no report)
sentinel fix . --ai --dry-run             # AI preview

# ── AI FEATURES ───────────────────────────────────────────────────────────
sentinel scan . --ai                      # AI fixes + explanations
sentinel scan . --ai-deep                 # AI scans every file for unknown patterns
sentinel scan . --ai-explain              # AI prose explanation for each finding
sentinel explain views.py 42              # AI explanation of a single line

# ── CI / BUILD GATES ─────────────────────────────────────────────────────
sentinel scan . --fail-on critical        # exit 1 on CRITICAL
sentinel scan . --fail-on high            # exit 1 on HIGH or above (recommended)
sentinel scan . --fail-on medium          # strict mode
sentinel scan . --diff --fail-on high     # PR gate: new code only

# ── GITHUB PR ────────────────────────────────────────────────────────────
sentinel scan . --pr-comment              # post summary comment
sentinel scan . --pr-inline               # post inline code annotations
sentinel scan . --pr-check                # create Check Run (pass/fail)
sentinel scan . --pr-comment --pr-inline --pr-check --ai  # full integration
sentinel scan . --gh-repo owner/repo --gh-pr 42 --gh-sha abc123

# ── GIT HOOKS ────────────────────────────────────────────────────────────
sentinel install-hooks                    # install pre-commit + pre-push
sentinel install-hooks --hooks pre-commit # only pre-commit
sentinel hook-status                      # check installation status
sentinel uninstall-hooks                  # remove, restore backups

# ── MODULE MODE ──────────────────────────────────────────────────────────
python -m djangosentinel scan .
python -m djangosentinel scan . --diff --base main --fix --ai
```

---

## Running Tests

```bash
# All 50 tests
python -m unittest discover tests -v

# By group
python -m unittest tests.test_all.TestDjangoScanner -v        # 18 tests
python -m unittest tests.test_all.TestBusinessLogicScanner -v  # 6 tests
python -m unittest tests.test_all.TestDependencyScanner -v     # 5 tests
python -m unittest tests.test_all.TestAutoFixer -v             # 2 tests
python -m unittest tests.test_all.TestReporters -v             # 3 tests
python -m unittest tests.test_all.TestDiffParser -v            # 7 tests
python -m unittest tests.test_all.TestDiffScanner -v           # 9 tests
```

---

## CI/CD — GitHub Actions

The included workflow has four jobs:

| Job | Trigger | Does |
|-----|---------|------|
| `security-scan` | every push/PR | SARIF upload, PR comment, inline, check run |
| `test` | every push/PR | 50 unit tests on Python 3.8–3.12 |
| `ai-deep-scan` | main branch only | Full AI deep scan, artifact upload |
| `dependency-check` | every push/PR | CVE report artifact |

Set these repository secrets:
- `ANTHROPIC_API_KEY` — for AI features (optional)
- `GITHUB_TOKEN` — auto-provided by GitHub Actions

---

## Adding Custom Rules

```python
# my_rules.py
import re, uuid
from pathlib import Path
from djangosentinel.models import Vulnerability, VulnCategory, Severity, CodeLocation, Fix

class MyScanner:
    def __init__(self, project_path):
        self.project_path = Path(project_path)
        self.vulnerabilities = []

    def scan(self):
        for py_file in self.project_path.rglob("*.py"):
            source = py_file.read_text()
            rel = str(py_file.relative_to(self.project_path))
            for i, line in enumerate(source.splitlines(), 1):
                if "my_dangerous_function(" in line:
                    self.vulnerabilities.append(Vulnerability(
                        vuln_id=str(uuid.uuid4())[:8],
                        title="Dangerous Function Used",
                        category=VulnCategory.INJECTION,
                        severity=Severity.HIGH,
                        location=CodeLocation(rel, i, snippet=line.strip()),
                        description="my_dangerous_function() is unsafe because ...",
                        owasp_ref="A03:2021 – Injection",
                        cwe_id="CWE-78",
                    ))
        return self.vulnerabilities
```

See `docs/CUSTOM_RULES.md` for full guide including CVE database additions, testing patterns, and severity guidelines.

---

## ⚠️ Disclaimer

DjangoSentinel is a static analysis (SAST) tool. It identifies code patterns that **look** vulnerable — it does not execute your code or simulate live attacks. Always combine with:
- Manual code review
- Penetration testing
- Runtime security monitoring

---

## License

MIT — free to use, modify, and distribute.
