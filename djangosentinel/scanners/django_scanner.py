"""
Django-specific vulnerability scanner.
Detects Django configuration issues, ORM misuse, template injection,
CSRF bypasses, middleware problems, and more.
"""

import ast
import re
import os
from pathlib import Path
from typing import List, Optional, Tuple
import uuid

from djangosentinel.models import (
    Vulnerability, VulnCategory, Severity, CodeLocation, Fix
)


class DjangoScanner:
    """Scans Django projects for framework-specific vulnerabilities."""

    SETTINGS_CHECKS = {
        "DEBUG": {
            "pattern": r"DEBUG\s*=\s*True",
            "severity": Severity.CRITICAL,
            "title": "DEBUG=True in Production Settings",
            "description": (
                "Django DEBUG mode exposes stack traces, SQL queries, local variables, "
                "and settings to any user who triggers an error. This is a critical "
                "information disclosure vulnerability in production environments."
            ),
            "owasp": "A05:2021 – Security Misconfiguration",
            "cwe": "CWE-94",
            "fix_original": "DEBUG = True",
            "fix_replacement": "DEBUG = False",
        },
        "SECRET_KEY_WEAK": {
            "pattern": r"SECRET_KEY\s*=\s*['\"](?:django-insecure|your-secret-key|changeme|secret|1234|password)[^'\"]*['\"]",
            "severity": Severity.CRITICAL,
            "title": "Weak or Default Django SECRET_KEY",
            "description": (
                "The Django SECRET_KEY is used for cryptographic signing of sessions, "
                "CSRF tokens, and password reset links. A weak or default key allows "
                "attackers to forge sessions and bypass security mechanisms."
            ),
            "owasp": "A02:2021 – Cryptographic Failures",
            "cwe": "CWE-321",
        },
        "ALLOWED_HOSTS_WILDCARD": {
            "pattern": r"ALLOWED_HOSTS\s*=\s*\[['\"]\*['\"]\]",
            "severity": Severity.HIGH,
            "title": "ALLOWED_HOSTS Wildcard (*) Permits Host Header Injection",
            "description": (
                "Setting ALLOWED_HOSTS = ['*'] disables Django's host header validation, "
                "making the application vulnerable to Host Header Injection attacks which "
                "can lead to cache poisoning, SSRF, and password reset poisoning."
            ),
            "owasp": "A05:2021 – Security Misconfiguration",
            "cwe": "CWE-20",
        },
        "CSRF_DISABLED": {
            "pattern": r"['\"]django\.middleware\.csrf\.CsrfViewMiddleware['\"]",
            "negate": True,
            "severity": Severity.HIGH,
            "title": "CSRF Middleware Missing from MIDDLEWARE",
            "description": (
                "CsrfViewMiddleware is not present in MIDDLEWARE. Without CSRF protection, "
                "attackers can trick authenticated users into executing unwanted actions."
            ),
            "owasp": "A01:2021 – Broken Access Control",
            "cwe": "CWE-352",
        },
        "SECURE_HSTS_MISSING": {
            "pattern": r"SECURE_HSTS_SECONDS\s*=\s*0",
            "severity": Severity.MEDIUM,
            "title": "HSTS Not Configured (SECURE_HSTS_SECONDS=0)",
            "description": (
                "HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS. "
                "Without it, users can be downgraded to HTTP connections via MITM attacks."
            ),
            "owasp": "A05:2021 – Security Misconfiguration",
            "cwe": "CWE-319",
            "fix_original": "SECURE_HSTS_SECONDS = 0",
            "fix_replacement": "SECURE_HSTS_SECONDS = 31536000  # 1 year",
        },
        "SESSION_COOKIE_INSECURE": {
            "pattern": r"SESSION_COOKIE_SECURE\s*=\s*False",
            "severity": Severity.HIGH,
            "title": "Session Cookie Transmitted Over HTTP",
            "description": (
                "SESSION_COOKIE_SECURE=False allows session cookies to be transmitted "
                "over unencrypted HTTP connections, exposing them to network eavesdroppers."
            ),
            "owasp": "A02:2021 – Cryptographic Failures",
            "cwe": "CWE-614",
            "fix_original": "SESSION_COOKIE_SECURE = False",
            "fix_replacement": "SESSION_COOKIE_SECURE = True",
        },
        "CSRF_COOKIE_INSECURE": {
            "pattern": r"CSRF_COOKIE_SECURE\s*=\s*False",
            "severity": Severity.MEDIUM,
            "title": "CSRF Cookie Not Secured",
            "description": "CSRF_COOKIE_SECURE=False allows CSRF tokens over HTTP.",
            "owasp": "A05:2021 – Security Misconfiguration",
            "cwe": "CWE-614",
            "fix_original": "CSRF_COOKIE_SECURE = False",
            "fix_replacement": "CSRF_COOKIE_SECURE = True",
        },
        "CLICKJACKING_DISABLED": {
            "pattern": r"X_FRAME_OPTIONS\s*=\s*['\"]ALLOW(?:ALL)?['\"]",
            "severity": Severity.MEDIUM,
            "title": "Clickjacking Protection Disabled (X_FRAME_OPTIONS)",
            "description": (
                "Setting X_FRAME_OPTIONS to ALLOW or ALLOWALL disables clickjacking "
                "protection, allowing the site to be embedded in iframes on attacker-controlled pages."
            ),
            "owasp": "A05:2021 – Security Misconfiguration",
            "cwe": "CWE-1021",
            "fix_original": 'X_FRAME_OPTIONS = "ALLOWALL"',
            "fix_replacement": 'X_FRAME_OPTIONS = "DENY"',
        },
        "CORS_ALLOW_ALL": {
            "pattern": r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True",
            "severity": Severity.HIGH,
            "title": "CORS Configured to Allow All Origins",
            "description": (
                "CORS_ALLOW_ALL_ORIGINS=True allows any website to make cross-origin "
                "requests to your API, bypassing the Same-Origin Policy."
            ),
            "owasp": "A05:2021 – Security Misconfiguration",
            "cwe": "CWE-942",
            "fix_original": "CORS_ALLOW_ALL_ORIGINS = True",
            "fix_replacement": (
                "CORS_ALLOW_ALL_ORIGINS = False\n"
                "CORS_ALLOWED_ORIGINS = [\n"
                '    "https://yourdomain.com",\n'
                "]"
            ),
        },
        "PASSWORD_HASHERS_WEAK": {
            "pattern": r"['\"]django\.contrib\.auth\.hashers\.MD5PasswordHasher['\"]",
            "severity": Severity.CRITICAL,
            "title": "MD5 Password Hasher in Use",
            "description": (
                "MD5 is a cryptographically broken hash function. Using it for password "
                "storage allows offline dictionary attacks to crack passwords almost instantly."
            ),
            "owasp": "A02:2021 – Cryptographic Failures",
            "cwe": "CWE-916",
        },
        "CONTENT_TYPE_NOSNIFF_MISSING": {
            "pattern": r"SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False",
            "severity": Severity.LOW,
            "title": "X-Content-Type-Options Header Not Sent",
            "description": (
                "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff "
                "responses, potentially executing uploaded files as scripts."
            ),
            "owasp": "A05:2021 – Security Misconfiguration",
            "cwe": "CWE-16",
            "fix_original": "SECURE_CONTENT_TYPE_NOSNIFF = False",
            "fix_replacement": "SECURE_CONTENT_TYPE_NOSNIFF = True",
        },
    }

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.vulnerabilities: List[Vulnerability] = []

    def scan(self) -> List[Vulnerability]:
        self.vulnerabilities = []

        for py_file in self.project_path.rglob("*.py"):
            if self._is_excluded(py_file):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(py_file.relative_to(self.project_path))

                if self._is_settings_file(py_file):
                    self._scan_settings(source, rel_path)

                self._scan_views(source, rel_path, py_file)
                self._scan_models(source, rel_path)
                self._scan_urls(source, rel_path)
                self._scan_templates_in_python(source, rel_path)
                self._scan_hardcoded_secrets(source, rel_path)
                self._scan_dangerous_functions(source, rel_path)

            except Exception:
                continue

        for html_file in self.project_path.rglob("*.html"):
            if self._is_excluded(html_file):
                continue
            try:
                source = html_file.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(html_file.relative_to(self.project_path))
                self._scan_templates(source, rel_path)
            except Exception:
                continue

        return self.vulnerabilities

    def _is_excluded(self, path: Path) -> bool:
        excludes = {"venv", ".venv", "env", ".env", "node_modules", "__pycache__", ".git", "migrations"}
        return any(part in excludes for part in path.parts)

    def _is_settings_file(self, path: Path) -> bool:
        return "settings" in path.stem.lower() or path.stem == "config"

    def _scan_settings(self, source: str, file_path: str):
        for check_name, check in self.SETTINGS_CHECKS.items():
            pattern = check["pattern"]
            matches = list(re.finditer(pattern, source, re.IGNORECASE))

            if check.get("negate"):
                # Flag if pattern NOT found
                if not matches:
                    line_num = 1
                    for i, line in enumerate(source.splitlines(), 1):
                        if "MIDDLEWARE" in line:
                            line_num = i
                            break
                    fix = None
                    if "fix_original" in check:
                        fix = Fix(
                            description=f"Add {check['fix_original']} to MIDDLEWARE",
                            original_code=check["fix_original"],
                            fixed_code=check["fix_replacement"],
                            explanation="Add CsrfViewMiddleware to your MIDDLEWARE list.",
                        )
                    self.vulnerabilities.append(Vulnerability(
                        vuln_id=str(uuid.uuid4())[:8],
                        title=check["title"],
                        category=VulnCategory.CSRF,
                        severity=check["severity"],
                        location=CodeLocation(file_path, line_num, snippet="MIDDLEWARE = [...]"),
                        description=check["description"],
                        owasp_ref=check.get("owasp", ""),
                        cwe_id=check.get("cwe", ""),
                        fix=fix,
                    ))
                continue

            for match in matches:
                line_num = source[: match.start()].count("\n") + 1
                snippet = match.group(0)

                fix = None
                if "fix_original" in check:
                    fix = Fix(
                        description=f"Replace insecure setting",
                        original_code=check["fix_original"],
                        fixed_code=check["fix_replacement"],
                        explanation=f"Change {check['fix_original']} to {check['fix_replacement']}",
                    )

                category_map = {
                    "A01": VulnCategory.AUTH,
                    "A02": VulnCategory.SENSITIVE_DATA,
                    "A05": VulnCategory.MISCONFIG,
                }
                owasp = check.get("owasp", "")
                category = next(
                    (v for k, v in category_map.items() if k in owasp),
                    VulnCategory.MISCONFIG,
                )

                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title=check["title"],
                    category=category,
                    severity=check["severity"],
                    location=CodeLocation(file_path, line_num, snippet=snippet),
                    description=check["description"],
                    owasp_ref=owasp,
                    cwe_id=check.get("cwe", ""),
                    fix=fix,
                ))

    def _scan_views(self, source: str, file_path: str, py_file: Path):
        """Detect view-level vulnerabilities."""
        lines = source.splitlines()

        # Raw SQL in views
        raw_sql_pattern = re.compile(
            r'\.raw\(|execute\(|cursor\(\).*?execute|RawSQL\(',
            re.DOTALL,
        )
        format_sql_pattern = re.compile(
            r'(SELECT|INSERT|UPDATE|DELETE|DROP).*?(\{[^}]|%s|\.format\()',
            re.IGNORECASE,
        )

        for i, line in enumerate(lines, 1):
            # Detect raw SQL with string formatting (injection risk)
            if format_sql_pattern.search(line):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="SQL Injection via String Formatting",
                    category=VulnCategory.INJECTION,
                    severity=Severity.CRITICAL,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "SQL query constructed using string formatting allows attackers "
                        "to inject arbitrary SQL. Use Django ORM or parameterized queries instead."
                    ),
                    owasp_ref="A03:2021 – Injection",
                    cwe_id="CWE-89",
                    fix=Fix(
                        description="Use parameterized queries",
                        original_code=line.strip(),
                        fixed_code="# Use Django ORM: Model.objects.filter(field=value)\n"
                                    "# Or parameterized: cursor.execute('SELECT ... WHERE id=%s', [user_id])",
                        explanation="Never interpolate user input directly into SQL strings.",
                        manual_review_required=True,
                    ),
                ))

            # Detect open redirect
            if re.search(r'redirect\(request\.(GET|POST)\[', line):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Open Redirect via User-Controlled Input",
                    category=VulnCategory.OPEN_REDIRECT,
                    severity=Severity.MEDIUM,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "Redirecting to a URL from user input without validation enables "
                        "phishing attacks by abusing your domain as a trusted redirector."
                    ),
                    owasp_ref="A01:2021 – Broken Access Control",
                    cwe_id="CWE-601",
                    fix=Fix(
                        description="Validate redirect URL before redirecting",
                        original_code=line.strip(),
                        fixed_code=(
                            "from django.utils.http import url_has_allowed_host_and_scheme\n"
                            "next_url = request.GET.get('next', '/')\n"
                            "if url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):\n"
                            "    return redirect(next_url)\n"
                            "return redirect('/')"
                        ),
                        explanation="Validate redirect URLs against an allowlist.",
                    ),
                ))

            # Detect CSRF exempt decorator misuse
            if "@csrf_exempt" in line:
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="CSRF Protection Explicitly Disabled on View",
                    category=VulnCategory.CSRF,
                    severity=Severity.HIGH,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "@csrf_exempt disables CSRF protection for this view. "
                        "Unless this is a verified webhook endpoint with alternative "
                        "authentication, this is a CSRF vulnerability."
                    ),
                    owasp_ref="A01:2021 – Broken Access Control",
                    cwe_id="CWE-352",
                    fix=Fix(
                        description="Remove @csrf_exempt or add webhook signature verification",
                        original_code="@csrf_exempt",
                        fixed_code=(
                            "# Option 1: Remove @csrf_exempt (preferred)\n"
                            "# Option 2: Add webhook signature verification:\n"
                            "# import hmac, hashlib\n"
                            "# sig = request.headers.get('X-Signature')\n"
                            "# if not hmac.compare_digest(sig, compute_sig(request.body)):\n"
                            "#     return HttpResponse(status=403)"
                        ),
                        manual_review_required=True,
                        explanation="Only use @csrf_exempt with verified signature-based auth.",
                    ),
                ))

            # Detect mass assignment via ModelForm with all fields
            if "__all__" in line and "fields" in line:
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Mass Assignment via fields='__all__'",
                    category=VulnCategory.MASS_ASSIGNMENT,
                    severity=Severity.HIGH,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "Using fields='__all__' in ModelForm exposes all model fields "
                        "to user input, including privileged fields like is_admin, is_staff, "
                        "or balance that should never be user-controlled."
                    ),
                    owasp_ref="A01:2021 – Broken Access Control",
                    cwe_id="CWE-915",
                    fix=Fix(
                        description="Explicitly list allowed fields",
                        original_code="fields = '__all__'",
                        fixed_code=(
                            "# Explicitly list only the fields users should control:\n"
                            "fields = ['username', 'email', 'bio']  # NOT is_admin, is_staff, balance"
                        ),
                        explanation="Always whitelist fields instead of using __all__.",
                    ),
                ))

            # Detect shell=True in subprocess
            if re.search(r'subprocess\.(run|call|Popen|check_output).*shell\s*=\s*True', line):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Command Injection via shell=True in subprocess",
                    category=VulnCategory.INJECTION,
                    severity=Severity.CRITICAL,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "subprocess with shell=True passes commands through the shell, "
                        "allowing command injection if any part of the command includes "
                        "user-controlled input."
                    ),
                    owasp_ref="A03:2021 – Injection",
                    cwe_id="CWE-78",
                    fix=Fix(
                        description="Use shell=False with argument list",
                        original_code="shell=True",
                        fixed_code="shell=False  # Pass args as list: subprocess.run(['cmd', arg1, arg2])",
                        explanation="Pass arguments as a list to avoid shell interpretation.",
                    ),
                ))

            # Detect IDOR - accessing objects without ownership check
            if re.search(r'get\(pk\s*=\s*request\.(GET|POST)\[', line) or \
                re.search(r'get\(id\s*=\s*request\.(GET|POST)\[', line):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Potential IDOR – Object Lookup Without Authorization",
                    category=VulnCategory.IDOR,
                    severity=Severity.HIGH,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "Fetching objects directly by user-supplied ID without verifying "
                        "ownership allows users to access other users' data by simply "
                        "changing the ID parameter."
                    ),
                    owasp_ref="A01:2021 – Broken Access Control",
                    cwe_id="CWE-639",
                    fix=Fix(
                        description="Add ownership check to object lookup",
                        original_code=line.strip(),
                        fixed_code=(
                            "# Filter by current user to prevent IDOR:\n"
                            "obj = get_object_or_404(MyModel, pk=pk, user=request.user)\n"
                            "# Or: MyModel.objects.filter(user=request.user).get(pk=pk)"
                        ),
                        explanation="Always scope queries to the current authenticated user.",
                        manual_review_required=True,
                    ),
                ))

    def _scan_models(self, source: str, file_path: str):
        """Detect model-level vulnerabilities."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            # Detect FileField with no upload_to (stores in root MEDIA_ROOT)
            if re.search(r'FileField\(\)|ImageField\(\)', line):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="FileField Without upload_to Path Restriction",
                    category=VulnCategory.MISCONFIG,
                    severity=Severity.LOW,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "FileField without upload_to stores files in the root of MEDIA_ROOT "
                        "and may expose uploaded files without proper access control."
                    ),
                    owasp_ref="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-552",
                    fix=Fix(
                        description="Specify upload_to directory",
                        original_code="FileField()",
                        fixed_code="FileField(upload_to='uploads/%Y/%m/%d/')",
                        explanation="Use upload_to to organize and control file storage paths.",
                    ),
                ))

    def _scan_urls(self, source: str, file_path: str):
        """Detect URL configuration vulnerabilities."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            # Detect overly permissive URL patterns
            if re.search(r"path\(.*\.\+.*\)", line) or re.search(r"re_path.*\.\*", line):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Overly Permissive URL Pattern",
                    category=VulnCategory.MISCONFIG,
                    severity=Severity.LOW,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "Overly broad URL patterns may match unintended paths and expose "
                        "views to unexpected inputs."
                    ),
                    owasp_ref="A05:2021 – Security Misconfiguration",
                    cwe_id="CWE-20",
                    fix=Fix(
                        description="Use specific URL patterns",
                        original_code=line.strip(),
                        fixed_code="# Use specific patterns: path('<int:pk>/', view)",
                        manual_review_required=True,
                        explanation="Restrict URL patterns to expected formats.",
                    ),
                ))

    def _scan_templates_in_python(self, source: str, file_path: str):
        """Detect server-side template injection risks in Python code."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            # Template injection via string interpolation
            if re.search(r'Template\(.*%.*\)|Template\(.*format\(|Template\(f["\']', line):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Server-Side Template Injection (SSTI)",
                    category=VulnCategory.INJECTION,
                    severity=Severity.CRITICAL,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "Constructing Django templates from user-controlled strings enables "
                        "Server-Side Template Injection (SSTI), allowing attackers to execute "
                        "arbitrary Python code on the server."
                    ),
                    owasp_ref="A03:2021 – Injection",
                    cwe_id="CWE-94",
                    fix=Fix(
                        description="Use static template with context variables",
                        original_code=line.strip(),
                        fixed_code=(
                            "# NEVER construct templates from user input\n"
                            "# Use static template file with context:\n"
                            "return render(request, 'myapp/template.html', context)"
                        ),
                        explanation="Templates must be static files; user data goes in context only.",
                    ),
                ))

    def _scan_hardcoded_secrets(self, source: str, file_path: str):
        """Detect hardcoded credentials and secrets."""
        secret_patterns = [
            (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded Password"),
            (r'(?:api_key|apikey|api-key)\s*=\s*["\'][A-Za-z0-9\-_]{16,}["\']', "Hardcoded API Key"),
            (r'(?:secret|secret_key)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded Secret Key"),
            (r'(?:aws_access_key_id|aws_secret)\s*=\s*["\'][A-Z0-9]{20,}["\']', "Hardcoded AWS Credential"),
            (r'(?:database_url|db_url)\s*=\s*["\'](?:postgres|mysql|mongodb)://[^"\']+["\']', "Hardcoded Database URL"),
            (r'Bearer\s+[A-Za-z0-9\-._~+/]{20,}', "Hardcoded Bearer Token"),
        ]
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            if "test" in file_path.lower() or "example" in file_path.lower():
                continue
            for pattern, name in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.vulnerabilities.append(Vulnerability(
                        vuln_id=str(uuid.uuid4())[:8],
                        title=f"{name} in Source Code",
                        category=VulnCategory.HARDCODED_SECRET,
                        severity=Severity.CRITICAL,
                        location=CodeLocation(file_path, i, snippet="[REDACTED]"),
                        description=(
                            f"A {name.lower()} is hardcoded in source code. "
                            "This credential will be exposed to anyone with repository access "
                            "and will persist in git history even after removal."
                        ),
                        owasp_ref="A02:2021 – Cryptographic Failures",
                        cwe_id="CWE-798",
                        fix=Fix(
                            description="Move secret to environment variable",
                            original_code=line.strip(),
                            fixed_code=(
                                "import os\n"
                                "from decouple import config  # pip install python-decouple\n\n"
                                "# In .env file (add to .gitignore):\n"
                                "# MY_SECRET=your-actual-secret\n\n"
                                "SECRET = config('MY_SECRET')\n"
                                "# Or: SECRET = os.environ.get('MY_SECRET')"
                            ),
                            explanation="Use environment variables or a secrets manager.",
                        ),
                    ))

    def _scan_dangerous_functions(self, source: str, file_path: str):
        """Detect use of dangerous Python/Django functions."""
        dangerous = [
            (r'\beval\s*\(', "Use of eval()", Severity.CRITICAL, "CWE-78",
            "eval() executes arbitrary Python code. Replace with safe alternatives."),
            (r'\bexec\s*\(', "Use of exec()", Severity.CRITICAL, "CWE-78",
            "exec() executes arbitrary Python code. Never use with user input."),
            (r'\bpickle\.loads\s*\(', "Unsafe Deserialization via pickle", Severity.CRITICAL, "CWE-502",
            "pickle.loads() can execute arbitrary code when deserializing untrusted data."),
            (r'\byaml\.load\s*\((?!.*Loader)', "Unsafe YAML Deserialization", Severity.HIGH, "CWE-502",
            "yaml.load() without Loader=yaml.SafeLoader can execute arbitrary code."),
            (r'\bos\.system\s*\(', "OS Command Execution via os.system()", Severity.HIGH, "CWE-78",
            "os.system() is vulnerable to command injection. Use subprocess with shell=False."),
            (r'mark_safe\(.*request\.(GET|POST)', "XSS via mark_safe with User Input", Severity.CRITICAL, "CWE-79",
            "mark_safe() with user-controlled data bypasses Django's auto-escaping, causing XSS."),
        ]
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, title, severity, cwe, desc in dangerous:
                if re.search(pattern, line):
                    self.vulnerabilities.append(Vulnerability(
                        vuln_id=str(uuid.uuid4())[:8],
                        title=title,
                        category=VulnCategory.INJECTION,
                        severity=severity,
                        location=CodeLocation(file_path, i, snippet=line.strip()),
                        description=desc,
                        owasp_ref="A03:2021 – Injection",
                        cwe_id=cwe,
                        fix=Fix(
                            description=f"Remove dangerous function: {title}",
                            original_code=line.strip(),
                            fixed_code="# See description for safe alternatives",
                            manual_review_required=True,
                            explanation=desc,
                        ),
                    ))

    def _scan_templates(self, source: str, file_path: str):
        """Scan HTML templates for XSS and other issues."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            # Detect autoescape off
            if "{% autoescape off %}" in line:
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Auto-Escaping Disabled in Template",
                    category=VulnCategory.XSS,
                    severity=Severity.HIGH,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "{% autoescape off %} disables Django's XSS protection for all "
                        "variables within the block, allowing stored and reflected XSS."
                    ),
                    owasp_ref="A03:2021 – Injection",
                    cwe_id="CWE-79",
                    fix=Fix(
                        description="Remove autoescape off or use |safe only on trusted content",
                        original_code="{% autoescape off %}",
                        fixed_code=(
                            "{# Remove autoescape off. If you need unescaped HTML, ensure it's "
                            "from a trusted source only, and use |safe on individual variables. #}"
                        ),
                        explanation="Rely on Django's default auto-escaping for all user content.",
                    ),
                ))

            # Detect |safe filter on potentially user-controlled variables
            if "|safe" in line and re.search(r'\{\{.*\b(user|request|input|data|content|html)\b.*\|safe', line, re.IGNORECASE):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Potential XSS via |safe Filter on User-Controlled Variable",
                    category=VulnCategory.XSS,
                    severity=Severity.HIGH,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "The |safe filter bypasses Django's auto-escaping. Using it on "
                        "user-controlled content enables stored/reflected XSS attacks."
                    ),
                    owasp_ref="A03:2021 – Injection",
                    cwe_id="CWE-79",
                    fix=Fix(
                        description="Remove |safe filter from user-controlled variables",
                        original_code=line.strip(),
                        fixed_code=line.strip().replace("|safe", ""),
                        explanation="Remove |safe and let Django auto-escape user content.",
                    ),
                ))
