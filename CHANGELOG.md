# Changelog

All notable changes to DjangoSentinel will be documented here.

## [1.0.0] — 2024-01-01

### Added

**Django Scanner**
- `DEBUG=True` in production detection (CRITICAL)
- Weak / default `SECRET_KEY` detection (CRITICAL)
- `ALLOWED_HOSTS = ['*']` wildcard detection (HIGH)
- Missing CSRF middleware detection (HIGH)
- Insecure session/CSRF cookie configuration (HIGH/MEDIUM)
- Missing HSTS configuration (MEDIUM)
- Clickjacking protection disabled (MEDIUM)
- CORS wildcard `ALLOWED_ORIGINS` (HIGH)
- MD5 password hasher detection (CRITICAL)
- X-Content-Type-Options missing (LOW)
- SQL injection via f-string/format in queries (CRITICAL)
- Server-Side Template Injection (SSTI) via dynamic Template() (CRITICAL)
- XSS via `mark_safe()` with user input (CRITICAL)
- `@csrf_exempt` misuse on sensitive endpoints (HIGH)
- Open redirect from user-controlled input (MEDIUM)
- Mass assignment via `fields='__all__'` (HIGH)
- IDOR — object lookup without ownership check (HIGH)
- `subprocess` with `shell=True` (CRITICAL)
- `eval()` / `exec()` usage (CRITICAL)
- `pickle.loads()` unsafe deserialization (CRITICAL)
- `yaml.load()` without SafeLoader (HIGH)
- `os.system()` command execution (HIGH)
- Hardcoded passwords, API keys, secrets, AWS credentials, DB URLs (CRITICAL)
- XSS via `{% autoescape off %}` in templates (HIGH)
- XSS via `|safe` filter on user-controlled variables (HIGH)
- FileField without `upload_to` restriction (LOW)
- Overly permissive URL patterns (LOW)

**Business Logic Scanner**
- Race condition in balance/inventory check without `select_for_update` (HIGH)
- Float arithmetic for monetary values (MEDIUM)
- Negative price/quantity not validated from user input (HIGH)
- Privilege escalation via user-controlled role/permission fields (CRITICAL)
- Workflow state bypass — direct status update without state machine (HIGH)
- Coupon/promo code reuse not tracked per user (MEDIUM)
- Paginated queryset disclosing other users' data (MEDIUM)
- Timezone-naive datetime for token/link expiry (MEDIUM)
- Missing negative balance guard in withdrawal operations (HIGH)

**Dependency Scanner**
- CVE database for 12 packages: Django, DRF, Pillow, requests, PyYAML, cryptography, celery, urllib3, Jinja2, Werkzeug, SQLAlchemy, paramiko
- Dangerous module import detection: pickle, marshal, shelve, xml.etree, xmlrpc
- Supports: `requirements.txt`, `requirements-dev.txt`, `requirements/*.txt`, `Pipfile`, `pyproject.toml`, `setup.py`, `setup.cfg`

**Auto-Fixer**
- Deterministic fix application for safe issues
- Timestamped backup creation before any modification
- Dry-run mode (preview without applying)
- Fix report with per-file summary
- Manual-review flagging for context-dependent fixes

**Reporters**
- Terminal reporter with ANSI colors and severity grouping
- JSON reporter for machine consumption / CI pipelines
- HTML reporter with dark-theme security dashboard
- SARIF 2.1.0 reporter for GitHub Code Scanning integration

**Git Hooks**
- Pre-commit hook: scans staged files, blocks on CRITICAL
- Pre-push hook: full project scan, blocks on HIGH+
- Hook installer/uninstaller/status CLI commands
- Automatic backup of existing hooks

**CLI**
- `sentinel scan <path>` — full scan with format/output options
- `sentinel fix <path>` — scan + auto-fix
- `sentinel install-hooks` — git hook installation
- `sentinel uninstall-hooks` — hook removal
- `sentinel hook-status` — installation status check
- `--fail-on` flag for CI exit code control
- `--staged-only` for git hook integration
- `python -m djangosentinel` module invocation

**CI/CD**
- GitHub Actions workflow with SARIF upload
- Matrix testing across Python 3.8–3.12
- Separate dependency-check job
- HTML report artifact upload

**Tests**
- 30+ unit tests across all scanner types
- False positive regression tests
- Auto-fixer application tests
- Reporter output validation tests
