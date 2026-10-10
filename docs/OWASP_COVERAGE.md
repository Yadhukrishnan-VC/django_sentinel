# DjangoSentinel — OWASP Top 10 (2021) Coverage Map

## A01 — Broken Access Control

| Detection | Scanner | Severity | Auto-Fix |
|---|---|---|---|
| IDOR — object lookup without ownership check | Django | HIGH | ⚠️ Manual |
| Mass assignment via `fields='__all__'` | Django | HIGH | ✅ |
| `@csrf_exempt` on sensitive views | Django | HIGH | ⚠️ Manual |
| Open redirect from user input | Django | MEDIUM | ✅ |
| Privilege escalation via user-controlled role | Business Logic | CRITICAL | ⚠️ Manual |
| Workflow state bypass (skip payment/approval) | Business Logic | HIGH | ⚠️ Manual |
| Paginated queryset disclosing other users' data | Business Logic | MEDIUM | ⚠️ Manual |
| CBV missing `LoginRequiredMixin` | AST | MEDIUM | ⚠️ Manual |
| FBV missing `@login_required` on sensitive view | AST | MEDIUM | ⚠️ Manual |

## A02 — Cryptographic Failures

| Detection | Scanner | Severity | Auto-Fix |
|---|---|---|---|
| Weak / default `SECRET_KEY` | Django | CRITICAL | — |
| MD5 password hasher | Django | CRITICAL | — |
| Session cookies over HTTP | Django | HIGH | ✅ |
| CSRF cookie not secured | Django | MEDIUM | ✅ |
| Missing HSTS | Django | MEDIUM | ✅ |
| Hardcoded passwords, API keys, secrets | Django | CRITICAL | ✅ |
| Hardcoded AWS credentials | Django | CRITICAL | ✅ |
| Hardcoded database URLs | Django | CRITICAL | ✅ |
| `random.choice()` for security values | AST | HIGH | ✅ |
| `hashlib.md5()` / `hashlib.sha1()` for secrets | AST | HIGH | ✅ |
| `==` comparison of tokens (timing attack) | AST | HIGH | ✅ |
| `datetime.now()` for token expiry | Business Logic | MEDIUM | ✅ |

## A03 — Injection

| Detection | Scanner | Severity | Auto-Fix |
|---|---|---|---|
| SQL injection via f-string | Django | CRITICAL | ⚠️ Manual |
| Server-Side Template Injection (SSTI) | Django | CRITICAL | ⚠️ Manual |
| XSS via `mark_safe()` with user input | Django | CRITICAL | ⚠️ Manual |
| XSS via `{% autoescape off %}` | Django | HIGH | ✅ |
| XSS via `\|safe` on user-controlled variable | Django | HIGH | ✅ |
| Command injection via `shell=True` | Django | CRITICAL | ✅ |
| `os.system()` command execution | Django | HIGH | ⚠️ Manual |
| `eval()` / `exec()` usage | Django | CRITICAL | ⚠️ Manual |
| `yaml.load()` without SafeLoader | Django | HIGH | ⚠️ Manual |
| Log injection via f-string in logging call | AST | LOW | ✅ |
| `getattr(obj, user_input)` dynamic access | AST | HIGH | ✅ |

## A04 — Insecure Design

| Detection | Scanner | Severity | Auto-Fix |
|---|---|---|---|
| Race condition in balance/inventory check | Business Logic | HIGH | ✅ |
| Missing negative balance guard | Business Logic | HIGH | ✅ |
| Negative quantity/price not validated | Business Logic | HIGH | ✅ |
| Workflow state bypass | Business Logic | HIGH | ⚠️ Manual |
| Coupon/promo code reuse per user | Business Logic | MEDIUM | ⚠️ Manual |
| `float()` for monetary values | Business Logic | MEDIUM | ✅ |
| Mutable default args in security functions | AST | MEDIUM | ✅ |

## A05 — Security Misconfiguration

| Detection | Scanner | Severity | Auto-Fix |
|---|---|---|---|
| `DEBUG=True` in production | Django | CRITICAL | ✅ |
| `ALLOWED_HOSTS=['*']` wildcard | Django | HIGH | — |
| CORS wildcard `ALLOW_ALL_ORIGINS` | Django | HIGH | ✅ |
| Missing CSRF middleware | Django | HIGH | — |
| Clickjacking protection disabled | Django | MEDIUM | ✅ |
| X-Content-Type-Options not sent | Django | LOW | ✅ |
| FileField without `upload_to` | Django | LOW | ✅ |
| Overly permissive URL patterns | Django | LOW | ⚠️ Manual |
| Hardcoded private IP address | AST | LOW | ✅ |

## A06 — Vulnerable and Outdated Components

| Detection | Scanner | Severity | Auto-Fix |
|---|---|---|---|
| Django CVEs (multiple versions) | Dependency | CRITICAL/HIGH | Show upgrade |
| Pillow DoS / decompression bomb | Dependency | HIGH | Show upgrade |
| PyYAML RCE via unsafe load | Dependency | CRITICAL | Show upgrade |
| celery RCE via pickle serialization | Dependency | HIGH | Show upgrade |
| cryptography SSH attack | Dependency | HIGH | Show upgrade |
| requests header leakage | Dependency | MEDIUM | Show upgrade |
| Jinja2 XSS in xmlattr filter | Dependency | MEDIUM | Show upgrade |
| Werkzeug multipart DoS | Dependency | HIGH | Show upgrade |
| urllib3 cookie header leak | Dependency | MEDIUM | Show upgrade |
| paramiko Terrapin attack | Dependency | MEDIUM | Show upgrade |
| SQLAlchemy SQL injection via order_by | Dependency | HIGH | Show upgrade |
| DRF auth bypass | Dependency | HIGH | Show upgrade |
| Dangerous imports: pickle, marshal, shelve | Dependency | HIGH | ⚠️ Manual |

## A07 — Identification and Authentication Failures

| Detection | Scanner | Severity | Auto-Fix |
|---|---|---|---|
| Weak `SECRET_KEY` (session forgery) | Django | CRITICAL | — |
| MD5 password hasher | Django | CRITICAL | — |
| Session cookies over HTTP | Django | HIGH | ✅ |
| `==` comparison of tokens (timing attack) | AST | HIGH | ✅ |
| Silent `except: pass` in auth functions | AST | HIGH | ✅ |
| `assert` used as security gate | AST | HIGH | ✅ |
| `is True` in permission checks | AST | LOW | ✅ |
| `datetime.now()` for token expiry | Business Logic | MEDIUM | ✅ |
| CBV / FBV missing auth guard | AST | MEDIUM | ⚠️ Manual |

## A08 — Software and Data Integrity Failures

| Detection | Scanner | Severity | Auto-Fix |
|---|---|---|---|
| `pickle.loads()` unsafe deserialization | Django | CRITICAL | ⚠️ Manual |
| `yaml.load()` without SafeLoader | Django | HIGH | ⚠️ Manual |
| Dangerous imports: pickle, marshal, shelve | Dependency | HIGH | ⚠️ Manual |

## A09 — Security Logging and Monitoring Failures

| Detection | Scanner | Severity | Auto-Fix |
|---|---|---|---|
| Log injection via f-string in logging call | AST | LOW | ✅ |
| Silent `except: pass` hides security errors | AST | HIGH | ✅ |

> Full logging configuration scanning (missing audit logs, insecure log levels) planned for v1.1.

## A10 — Server-Side Request Forgery (SSRF)

> SSRF detection planned for v1.1 — will scan for user-controlled URLs passed to
> `requests.get()`, `httpx`, `urllib`, Django's HTTP client, and `socket.connect()`.

---

## Coverage Summary

| OWASP Category | Detections | Auto-fixable |
|----------------|-----------|--------------|
| A01 Broken Access Control | 9 | 3 |
| A02 Cryptographic Failures | 12 | 8 |
| A03 Injection | 11 | 5 |
| A04 Insecure Design | 7 | 5 |
| A05 Security Misconfiguration | 9 | 7 |
| A06 Vulnerable Components | 13 | 12 |
| A07 Auth Failures | 9 | 6 |
| A08 Integrity Failures | 3 | 0 |
| A09 Logging Failures | 2 | 2 |
| A10 SSRF | 0 | — |
| **Total** | **75** | **48** |
