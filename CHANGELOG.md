# Changelog

## [Unreleased]

### Fixed
- `ai_engine.py` had lost the `AIPatternScanner` and `PRReviewSummarizer` classes, so `--ai`, `--ai-deep` and `--pr-comment` failed with an ImportError. The module is restored and now talks to the provider layer (Anthropic, OpenAI, Google Gemini).
- Auto-fix for hard-coded secrets renamed `SECRET_KEY` to `SECRET` and needed a third-party package. It now keeps the variable name and reads it from `os.environ`; non-assignment cases are left for manual review.
- AI pattern scanner now skips files inside `migrations/` packages, as documented.
- "AI disabled" message now names all three supported API keys.
- Docker: the image is built from the local source (not from PyPI), has `production` and `development` targets, no restart loop, and a `.dockerignore`.

### Added
- `tests/test_ai_engine.py`: regression tests for the AI engine (fake provider) and the secret auto-fix.



All notable changes to DjangoSentinel are documented here.

---

## [1.0.0] — 2024-01-01

### Added — Core Infrastructure

**Data Models (`models.py`)**
- `Vulnerability` dataclass: id, title, category, severity, location, description, OWASP ref, CWE, CVE, fix, metadata
- `Fix` dataclass: original_code, fixed_code, applied, manual_review_required, explanation
- `CodeLocation` dataclass: file_path, line_number, column, end_line, snippet
- `ScanResult` dataclass with computed properties: critical_count, high_count, fixable_count, fixed_count
- `Severity` enum: CRITICAL, HIGH, MEDIUM, LOW, INFO
- `VulnCategory` enum: 15 categories covering OWASP Top 10

---

### Added — Rule-Based Scanner (`django_scanner.py`)

**Settings detections (11)**
- `DEBUG=True` in production — CRITICAL, auto-fixed
- Weak/default `SECRET_KEY` — CRITICAL
- `ALLOWED_HOSTS=['*']` wildcard — HIGH
- Missing CSRF middleware — HIGH
- `SESSION_COOKIE_SECURE=False` — HIGH, auto-fixed
- `CSRF_COOKIE_SECURE=False` — MEDIUM, auto-fixed
- `CORS_ALLOW_ALL_ORIGINS=True` — HIGH, auto-fixed
- `SECURE_HSTS_SECONDS=0` — MEDIUM, auto-fixed
- `X_FRAME_OPTIONS=ALLOWALL` — MEDIUM, auto-fixed
- `MD5PasswordHasher` — CRITICAL
- `SECURE_CONTENT_TYPE_NOSNIFF=False` — LOW, auto-fixed

**View detections (7)**
- SQL injection via f-string/format — CRITICAL, manual review
- Server-Side Template Injection via `Template(f"...")` — CRITICAL, manual review
- XSS via `mark_safe()` with user input — CRITICAL, manual review
- `@csrf_exempt` on sensitive views — HIGH, manual review
- Open redirect from unvalidated input — MEDIUM, auto-fixed
- Mass assignment via `fields='__all__'` — HIGH, auto-fixed
- IDOR — object lookup without ownership check — HIGH, manual review

**Dangerous functions (6)**
- `eval()` / `exec()` — CRITICAL, manual review
- `pickle.loads()` — CRITICAL, manual review
- `yaml.load()` without SafeLoader — HIGH, manual review
- `subprocess` with `shell=True` — CRITICAL, auto-fixed
- `os.system()` — HIGH, manual review
- `mark_safe()` with user-controlled data — CRITICAL, manual review

**Secret detection (6 patterns)**
- Hardcoded passwords, API keys, AWS credentials, DB URLs, bearer tokens — CRITICAL, auto-fixed

**Template detections (2)**
- `{% autoescape off %}` — HIGH, auto-fixed
- `{{ var|safe }}` on user-controlled variable — HIGH, auto-fixed

**Model/URL detections (2)**
- FileField without `upload_to` — LOW, auto-fixed
- Overly permissive URL patterns — LOW, manual review

---

### Added — Business Logic Scanner (`business_logic_scanner.py`)

- Race condition in balance/inventory check — HIGH, auto-fixed
- `float()` for monetary values — MEDIUM, auto-fixed
- Negative price/quantity not validated — HIGH, auto-fixed
- Privilege escalation via user-controlled role field — CRITICAL, manual review
- Workflow state bypass — HIGH, manual review
- Coupon/promo code reuse per user — MEDIUM, manual review
- Paginated queryset without user filter — MEDIUM, manual review
- `datetime.now()` for token expiry — MEDIUM, auto-fixed
- Missing negative balance guard — HIGH, auto-fixed

---

### Added — Dependency Scanner (`dependency_scanner.py`)

**CVE database — 12 packages**
- Django: CVE-2023-31047, CVE-2023-41164, CVE-2023-46695, CVE-2021-28658
- DRF: CVE-2023-28021
- Pillow: CVE-2022-45199, CVE-2023-44271
- requests: CVE-2023-32681
- PyYAML: CVE-2020-14343
- cryptography: CVE-2023-38325
- celery: CVE-2021-23727
- urllib3: CVE-2023-43804
- Jinja2: CVE-2024-22195
- Werkzeug: CVE-2023-46136
- SQLAlchemy: CVE-2019-7164
- paramiko: CVE-2023-48795

**Dangerous import detection**
- `pickle`, `marshal`, `shelve`, `xml.etree.ElementTree`, `xmlrpc` — HIGH

**File format support**
- `requirements.txt`, `requirements-dev.txt`, `requirements/*.txt`
- `Pipfile`, `pyproject.toml`, `setup.py`, `setup.cfg`

---

### Added — AST Structural Scanner (`ast_scanner.py`)

Uses Python's `ast` module to detect issues regex cannot find:
- CBV missing `LoginRequiredMixin` — MEDIUM, manual review
- FBV missing `@login_required` on sensitive views — MEDIUM, manual review
- `==` comparison of secrets/tokens (timing attack) — HIGH, auto-fixed
- Silent `except: pass` in auth/security functions — HIGH, auto-fixed
- `random.choice()` / `random.randint()` for security values — HIGH, auto-fixed
- `hashlib.md5()` / `hashlib.sha1()` for secrets — HIGH, auto-fixed
- `getattr(obj, user_input)` dynamic attribute access — HIGH, auto-fixed
- `assert` used as security gate — HIGH, auto-fixed
- Mutable default args in security functions — MEDIUM, auto-fixed
- Log injection via f-string in logging calls — LOW, auto-fixed
- Hardcoded private IP address — LOW, auto-fixed
- `is True` comparison in permission checks — LOW, auto-fixed

---

### Added — Git Diff Scanner (`diff_scanner.py`)

**DiffParser**
- Parses unified diff format (git diff, git diff --staged, .patch files)
- Extracts added lines per hunk with exact line numbers
- Tracks new files, deleted files, renamed files
- Handles multiple hunks per file, multiple files per diff

**DiffScanner**
- Runs all scanners on full file (for AST context)
- Filters findings to only changed/added lines
- For new files: all lines are scanned
- Dependency findings only included if requirements file is in diff
- Tags each finding with `diff_detected=True` metadata

**GitDiffSource**
- `staged` mode: `git diff --staged`
- `unstaged` mode: `git diff`
- `head` mode: `git diff HEAD`
- `branch` mode: `git diff <branch>`
- `range` mode: `git diff <sha1> <sha2>`
- `file` mode: reads a `.diff` or `.patch` file

---

### Added — AI Engine (`ai_engine.py`)

**AIFixEngine**
- Generates multi-line fixes for complex vulnerabilities
- Uses Claude claude-sonnet-4-20250514
- Response caching to avoid duplicate API calls
- Context extraction: 20 lines around each vulnerability
- Falls back gracefully when API key is not set

**AIExplainer**
- Generates developer-friendly "why is this risky" explanations
- Context-aware: references the actual code, not generic descriptions
- Max 150 words, plain prose, no jargon
- Caches responses per vulnerability ID

**AIPatternScanner**
- Submits code to Claude for security reasoning
- Detects novel/unknown patterns that regex cannot catch
- Skips boring files (migrations, admin, __init__, etc.)
- Returns structured `Vulnerability` objects from JSON response
- Filters AI results to diff lines in diff mode

**PRReviewSummarizer**
- Generates GitHub PR security review comment in Markdown
- AI-powered summary or template fallback (no API required)
- Includes severity table, findings list, fix status
- `post_to_github()` — posts via GitHub API, updates existing comment

---

### Added — GitHub PR Integration (`github_integration.py`)

**GitHubPRIntegration**
- Auto-detects `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_SHA`, PR number from environment
- `post_summary_comment()` — posts or updates PR summary comment
- `post_inline_review()` — inline code annotations on exact lines
- `create_check_run()` — creates pass/fail Check Run
- `get_pr_changed_files()` — fetches changed files from GitHub API
- Only annotates lines that are in the PR diff (no noise from unchanged code)
- `REQUEST_CHANGES` event for CRITICAL, `COMMENT` for lower severity

---

### Added — Fix Engine

**AutoFixer (`auto_fixer.py`)**
- Filters vulnerabilities by: has fix, not applied, not manual_review_required
- Creates timestamped backups before any modification
- Applies text replacement (exact match, then line-level fallback)
- `dry_run` mode: shows what would be fixed without touching files
- Generates per-file fix report

**ContextAwareFixer (`context_fixer.py`)**
- Separates rule-fixable from AI-needed vulnerabilities
- Extracts 20-line context window for AI fix generation
- Falls back to rule engine fix hint when AI unavailable
- Records fix outcomes per file for detailed reporting
- Returns `(rule_fixed, ai_fixed, manual_count)` tuple

---

### Added — Reporters (`reporters.py`)

**TerminalReporter**
- ANSI-coloured output grouped by severity
- Shows: id, CWE, OWASP ref, file:line, code snippet, description, fix hint
- Status badges: ✅ FIXED, 🔧 FIXABLE, ⚠️ MANUAL
- `--no-color` flag support

**DiffReporter**
- Diff-scope header: changed files, Python/HTML files, added lines count
- Changed files list with line counts
- Per-file grouped findings sorted by severity then line number
- AI badge for AI-detected findings
- AI explanation inline if available
- `report_json()` — JSON variant with diff metadata

**JSONReporter**
- Full ScanResult as JSON including all vulnerability fields
- Includes: severity, location, fix status, references

**HTMLReporter**
- Dark-theme browser dashboard
- Summary statistics cards
- Per-finding expandable blocks with code snippets and fix code
- Works for both full scan and diff scan results

**SARIFReporter**
- SARIF 2.1.0 format for GitHub Code Scanning
- Maps severity to SARIF levels: failure/warning/note
- Includes fix descriptions in SARIF fix blocks
- Produces inline PR annotations when uploaded to GitHub

---

### Added — Git Hooks (`git_hooks.py`)

**Pre-commit hook** (installed to `.git/hooks/pre-commit`)
- Runs `sentinel scan . --diff --staged --fail-on critical`
- Scans ONLY staged changes via diff mode
- Blocks commit if CRITICAL found
- Exits 0 (pass) if DjangoSentinel not installed

**Pre-push hook** (installed to `.git/hooks/pre-push`)
- Runs `sentinel scan . --diff --fail-on high`
- Full diff scan vs HEAD
- Blocks push if HIGH or CRITICAL found
- Pure Python — works on Windows, macOS, Linux

**HookInstaller**
- Installs, uninstalls, and checks status of hooks
- Backs up existing hooks before overwriting
- Restores backups on uninstall

---

### Added — CLI (`cli.py`)

**Commands**
- `sentinel scan <path>` — full or diff scan with all options
- `sentinel fix <path>` — scan + apply all fixes
- `sentinel explain <file> <line>` — AI explanation of specific line
- `sentinel install-hooks [path]` — install git hooks
- `sentinel uninstall-hooks [path]` — remove hooks
- `sentinel hook-status [path]` — check installation status

**Scan flags**
- `--diff`, `--staged`, `--base`, `--head`, `--diff-file` — diff mode controls
- `--fix`, `--dry-run` — fix controls
- `--ai`, `--ai-deep`, `--ai-explain` — AI controls
- `--format`, `-o` — output format and file
- `--fail-on` — CI exit code control
- `--skip-deps`, `--skip-logic`, `--skip-ast` — scanner toggles
- `--pr-comment`, `--pr-inline`, `--pr-check` — GitHub PR integration
- `--gh-token`, `--gh-repo`, `--gh-pr`, `--gh-sha` — GitHub credentials
- `--no-color` — plain text output

---

### Added — Configuration

**`.sentinel.yml`** — project config file with sections:
- `scan`: exclude_dirs, exclude_patterns, scanner toggles
- `ai`: enabled, deep_scan, explain, max_deep_scan_files
- `fix`: backup, backup_dir, auto_fix_level
- `ci`: fail_on, format, sarif_output
- `github`: pr_comment, pr_inline, pr_check, ai_pr_summary
- `hooks`: pre_commit_fail_on, pre_push_fail_on
- `ignore`: suppression list with file/line/reason

---

### Added — GitHub Actions (`.github/workflows/security.yml`)

Four jobs:
- `security-scan`: SARIF upload, PR comment, inline annotations, check run, HTML artifact
- `test`: 50 unit tests on Python 3.8, 3.9, 3.10, 3.11, 3.12
- `ai-deep-scan`: full AI scan on main branch, JSON artifact
- `dependency-check`: CVE-only scan, JSON artifact

---

### Added — Tests (`tests/test_all.py`)

**50 unit tests across 7 test classes**

- `TestDjangoScanner` — 18 tests (detection + false positive)
- `TestBusinessLogicScanner` — 6 tests
- `TestDependencyScanner` — 5 tests
- `TestAutoFixer` — 2 tests
- `TestReporters` — 3 tests
- `TestDiffParser` — 7 tests (diff parsing)
- `TestDiffScanner` — 9 tests (diff-scoped vulnerability detection)

---

### Added — Documentation

- `README.md` — complete user guide with architecture diagram
- `docs/OWASP_COVERAGE.md` — A01–A10 coverage map
- `docs/CI_INTEGRATION.md` — GitHub/GitLab/Jenkins/Bitbucket configs
- `docs/CUSTOM_RULES.md` — guide for adding custom detections
- `CONTRIBUTING.md` — development guide, severity guidelines, PR checklist
- `SECURITY.md` — responsible disclosure policy
- `CHANGELOG.md` — this file
