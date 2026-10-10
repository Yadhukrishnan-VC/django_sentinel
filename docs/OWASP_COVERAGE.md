# DjangoSentinel — OWASP Top 10 Coverage Map

## A01:2021 — Broken Access Control

| Detection | Scanner | Severity |
|---|---|---|
| IDOR — object lookup without ownership check | Django | HIGH |
| Mass assignment via `fields='__all__'` | Django | HIGH |
| `@csrf_exempt` on sensitive views | Django | HIGH |
| Open redirect from user input | Django | MEDIUM |
| Privilege escalation via user-controlled role | Business Logic | CRITICAL |
| Workflow state bypass | Business Logic | HIGH |
| Paginated queryset disclosing other users' data | Business Logic | MEDIUM |

## A02:2021 — Cryptographic Failures

| Detection | Scanner | Severity |
|---|---|---|
| Weak / default `SECRET_KEY` | Django | CRITICAL |
| MD5 password hasher | Django | CRITICAL |
| Session cookies over HTTP (`SESSION_COOKIE_SECURE=False`) | Django | HIGH |
| CSRF cookie not secured | Django | MEDIUM |
| Missing HSTS (`SECURE_HSTS_SECONDS=0`) | Django | MEDIUM |
| Hardcoded passwords / API keys / AWS credentials | Django | CRITICAL |
| Timezone-naive datetime for token expiry | Business Logic | MEDIUM |

## A03:2021 — Injection

| Detection | Scanner | Severity |
|---|---|---|
| SQL injection via f-string / string formatting | Django | CRITICAL |
| Server-Side Template Injection (SSTI) | Django | CRITICAL |
| Command injection via `shell=True` | Django | CRITICAL |
| `os.system()` command execution | Django | HIGH |
| `eval()` / `exec()` usage | Django | CRITICAL |
| XSS via `mark_safe()` with user input | Django | CRITICAL |
| XSS via `{% autoescape off %}` | Django | HIGH |
| XSS via `|safe` on user-controlled variables | Django | HIGH |
| `yaml.load()` without SafeLoader | Django | HIGH |

## A04:2021 — Insecure Design

| Detection | Scanner | Severity |
|---|---|---|
| Race condition in balance / inventory check | Business Logic | HIGH |
| Missing negative balance guard | Business Logic | HIGH |
| Negative quantity / price not validated | Business Logic | HIGH |
| Workflow state bypass (order status skip) | Business Logic | HIGH |
| Coupon / promo code reuse per user | Business Logic | MEDIUM |
| Float arithmetic for monetary values | Business Logic | MEDIUM |

## A05:2021 — Security Misconfiguration

| Detection | Scanner | Severity |
|---|---|---|
| `DEBUG=True` in production | Django | CRITICAL |
| `ALLOWED_HOSTS = ['*']` wildcard | Django | HIGH |
| CORS wildcard `ALLOW_ALL_ORIGINS` | Django | HIGH |
| Missing CSRF middleware | Django | HIGH |
| Clickjacking (`X_FRAME_OPTIONS=ALLOWALL`) | Django | MEDIUM |
| `X-Content-Type-Options` not sent | Django | LOW |
| FileField without `upload_to` | Django | LOW |
| Overly permissive URL patterns | Django | LOW |

## A06:2021 — Vulnerable and Outdated Components

| Detection | Scanner | Severity |
|---|---|---|
| Django CVEs (multiple versions) | Dependency | HIGH/CRITICAL |
| Pillow decompression bomb / DoS | Dependency | HIGH |
| PyYAML RCE via unsafe load | Dependency | CRITICAL |
| Celery RCE via pickle serialization | Dependency | HIGH |
| cryptography SSH attack | Dependency | HIGH |
| requests header leakage | Dependency | MEDIUM |
| Jinja2 XSS in xmlattr filter | Dependency | MEDIUM |
| Werkzeug multipart DoS | Dependency | HIGH |
| urllib3 cookie header leak | Dependency | MEDIUM |
| paramiko Terrapin attack | Dependency | MEDIUM |
| Dangerous imports: pickle, marshal, shelve, xmlrpc | Dependency | HIGH |

## A07:2021 — Identification and Authentication Failures

| Detection | Scanner | Severity |
|---|---|---|
| Weak `SECRET_KEY` (session forgery) | Django | CRITICAL |
| MD5 password hasher | Django | CRITICAL |
| Session cookies over HTTP | Django | HIGH |
| Timezone-naive token expiry | Business Logic | MEDIUM |

## A08:2021 — Software and Data Integrity Failures

| Detection | Scanner | Severity |
|---|---|---|
| `pickle.loads()` unsafe deserialization | Django | CRITICAL |
| `yaml.load()` without SafeLoader | Django | HIGH |
| Dangerous imports: pickle, marshal, shelve | Dependency | HIGH |

## A09:2021 — Security Logging and Monitoring Failures

> DjangoSentinel does not yet scan for logging configuration issues.
> Planned for v1.1.

## A10:2021 — Server-Side Request Forgery (SSRF)

> SSRF detection planned for v1.1 — scanning for user-controlled URLs
> passed to `requests.get()`, `httpx`, `urllib`, and Django's HTTP client.
