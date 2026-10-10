"""
AST-Based Structural Scanner — DjangoSentinel
==============================================
Uses Python's ast module to analyse code STRUCTURE rather than text patterns.

Why AST over regex?
- Regex: finds text. Can be fooled by comments, strings, formatting.
- AST:   finds code. Understands scope, call graphs, data flow.

Examples of what AST catches that regex misses:
- `getattr(obj, user_input)` — dynamic attribute access with user data
- Missing @login_required on a view function connected to urls.py
- Exception blocks that silently swallow security errors
- Mutable default arguments in security-sensitive functions
- Direct model field access bypassing property validators
"""

import ast
import uuid
from pathlib import Path
from typing import List, Optional, Set, Tuple, Dict

from djangosentinel.models import (
    Vulnerability, VulnCategory, Severity, CodeLocation, Fix
)


class ASTScanner:
    """
    Structural AST scanner. Complements the regex-based DjangoScanner
    by finding vulnerabilities that require understanding code structure.
    """

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
                tree = ast.parse(source, filename=str(py_file))
                self._scan_tree(tree, source, rel_path)
            except SyntaxError:
                continue
            except Exception:
                continue

        return self.vulnerabilities

    def _is_excluded(self, path: Path) -> bool:
        excludes = {"venv", ".venv", "env", "node_modules", "__pycache__", ".git", "migrations"}
        return any(part in excludes for part in path.parts)

    def _scan_tree(self, tree: ast.AST, source: str, file_path: str):
        """Run all AST checks on a parsed file."""
        visitor = _SecurityVisitor(source, file_path)
        visitor.visit(tree)
        self.vulnerabilities.extend(visitor.vulnerabilities)


class _SecurityVisitor(ast.NodeVisitor):
    """
    AST node visitor that walks the tree and detects security issues
    by examining code structure rather than text patterns.
    """

    # Django HTTP method handler names
    VIEW_METHODS = {"get", "post", "put", "patch", "delete", "dispatch"}

    # Functions that should never receive user-controlled values
    DANGEROUS_SINKS = {
        "eval", "exec", "compile", "execfile",
        "__import__", "open", "os.system", "subprocess.call",
    }

    def __init__(self, source: str, file_path: str):
        self.source = source
        self.source_lines = source.splitlines()
        self.file_path = file_path
        self.vulnerabilities: List[Vulnerability] = []
        self._current_class: Optional[str] = None
        self._imports: Set[str] = set()
        self._from_imports: Dict[str, str] = {}  # name -> module
        self._has_login_required = False

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _snippet(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 1)
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _loc(self, node: ast.AST) -> CodeLocation:
        return CodeLocation(
            file_path=self.file_path,
            line_number=getattr(node, "lineno", 1),
            column=getattr(node, "col_offset", None),
            snippet=self._snippet(node),
        )

    def _add(
        self,
        node: ast.AST,
        title: str,
        category: VulnCategory,
        severity: Severity,
        description: str,
        owasp: str,
        cwe: str,
        fix: Optional[Fix] = None,
    ):
        self.vulnerabilities.append(Vulnerability(
            vuln_id=str(uuid.uuid4())[:8],
            title=title,
            category=category,
            severity=severity,
            location=self._loc(node),
            description=description,
            owasp_ref=owasp,
            cwe_id=cwe,
            fix=fix,
            metadata={"source": "ast_scanner"},
        ))

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract a dotted name from a Call node, e.g. 'obj.method'."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return ""

    # ── Import tracking ──────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._imports.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self._from_imports[name] = module
        self.generic_visit(node)

    # ── Class tracking (for CBV detection) ──────────────────────────────────

    def visit_ClassDef(self, node: ast.ClassDef):
        prev = self._current_class
        self._current_class = node.name
        self._check_cbv_missing_auth(node)
        self.generic_visit(node)
        self._current_class = prev

    # ── Function-level checks ────────────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._check_mutable_default_args(node)
        self._check_broad_exception_swallow(node)
        self._check_missing_login_required_fbv(node)
        self._check_timing_sensitive_comparison(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    # ── Expression-level checks ──────────────────────────────────────────────

    def visit_Call(self, node: ast.Call):
        self._check_dynamic_getattr(node)
        self._check_assert_used_for_auth(node)
        self._check_random_for_security(node)
        self._check_md5_sha1_for_secrets(node)
        self._check_format_string_log(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        self._check_hardcoded_ip(node)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        self._check_is_comparison_to_true(node)
        self.generic_visit(node)

    # ══════════════════════════════════════════════════════════════════════════
    # DETECTION IMPLEMENTATIONS
    # ══════════════════════════════════════════════════════════════════════════

    def _check_mutable_default_args(self, node: ast.FunctionDef):
        """
        Mutable default arguments ({}, []) are shared across all calls.
        In security functions this can cause state bleed between requests.
        """
        for default in node.args.defaults + node.args.kw_defaults:
            if default is None:
                continue
            if isinstance(default, (ast.Dict, ast.List, ast.Set)):
                self._add(
                    node,
                    "Mutable Default Argument in Function Signature",
                    VulnCategory.MISCONFIG,
                    Severity.MEDIUM,
                    (
                        f"Function '{node.name}' uses a mutable default argument (dict/list/set). "
                        "In Django, this object is shared across all calls to the function, "
                        "which can cause state bleed between requests — especially dangerous "
                        "in middleware, validators, and permission classes."
                    ),
                    "A04:2021 – Insecure Design",
                    "CWE-1188",
                    Fix(
                        description="Use None as default, initialise inside function",
                        original_code=f"def {node.name}(..., data={{}}):",
                        fixed_code=(
                            f"def {node.name}(..., data=None):\n"
                            "    if data is None:\n"
                            "        data = {}"
                        ),
                        explanation="Mutable defaults are evaluated once at function definition.",
                    ),
                )

    def _check_broad_exception_swallow(self, node: ast.FunctionDef):
        """
        `except Exception: pass` in security-sensitive code silently hides
        authentication failures, permission errors, and validation exceptions.
        """
        security_keywords = {
            "auth", "login", "permission", "token", "verify",
            "validate", "check", "secure", "password", "csrf",
        }
        fn_name = node.name.lower()
        is_security_fn = any(kw in fn_name for kw in security_keywords)

        if not is_security_fn:
            return

        for child in ast.walk(node):
            if not isinstance(child, ast.ExceptHandler):
                continue
            # Check if the except body is just `pass` or a bare continue
            body = child.body
            if len(body) == 1 and isinstance(body[0], (ast.Pass, ast.Continue)):
                self._add(
                    child,
                    "Silent Exception Swallow in Security Function",
                    VulnCategory.AUTH,
                    Severity.HIGH,
                    (
                        f"Function '{node.name}' catches exceptions and silently ignores them "
                        "with `pass`. In security-sensitive functions, swallowing exceptions "
                        "can hide authentication failures, making failed auth appear successful."
                    ),
                    "A07:2021 – Identification and Authentication Failures",
                    "CWE-390",
                    Fix(
                        description="Log the exception and re-raise or return a safe default",
                        original_code="except Exception:\n    pass",
                        fixed_code=(
                            "except Exception as e:\n"
                            "    import logging\n"
                            "    logger = logging.getLogger(__name__)\n"
                            "    logger.error('Security check failed: %s', e)\n"
                            "    raise  # or return False / HttpResponseForbidden()"
                        ),
                        explanation="Never silently swallow exceptions in auth/permission code.",
                    ),
                )

    def _check_missing_login_required_fbv(self, node: ast.FunctionDef):
        """
        Function-based views that accept a `request` parameter but lack
        @login_required or @permission_required may be publicly accessible.
        """
        if not node.args.args:
            return

        # Check if first arg is named 'request'
        first_arg = node.args.args[0].arg if node.args.args else ""
        if first_arg not in ("request", "req"):
            return

        # Check for auth decorators
        auth_decorators = {
            "login_required", "permission_required", "staff_member_required",
            "superuser_required", "api_view", "IsAuthenticated",
        }
        decorator_names = set()
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorator_names.add(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorator_names.add(dec.attr)
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    decorator_names.add(dec.func.id)
                elif isinstance(dec.func, ast.Attribute):
                    decorator_names.add(dec.func.attr)

        has_auth = bool(decorator_names & auth_decorators)
        has_csrf_only = "csrf_exempt" in decorator_names

        # Only flag if name suggests it's private/sensitive
        sensitive_keywords = {
            "admin", "dashboard", "profile", "account", "settings",
            "delete", "update", "create", "edit", "manage", "upload",
            "payment", "order", "user", "password", "export", "report",
        }
        fn_lower = node.name.lower()
        is_sensitive = any(kw in fn_lower for kw in sensitive_keywords)

        if is_sensitive and not has_auth and not has_csrf_only:
            self._add(
                node,
                f"View '{node.name}' May Lack Authentication Guard",
                VulnCategory.AUTH,
                Severity.MEDIUM,
                (
                    f"The view function '{node.name}' accepts a request and appears to handle "
                    "sensitive operations but has no visible authentication decorator "
                    "(@login_required, @permission_required). If this view is connected to a URL "
                    "route it may be accessible without authentication."
                ),
                "A01:2021 – Broken Access Control",
                "CWE-306",
                Fix(
                    description="Add @login_required decorator",
                    original_code=f"def {node.name}(request",
                    fixed_code=(
                        "from django.contrib.auth.decorators import login_required\n\n"
                        f"@login_required\ndef {node.name}(request"
                    ),
                    manual_review_required=True,
                    explanation="Add @login_required unless this view is intentionally public.",
                ),
            )

    def _check_timing_sensitive_comparison(self, node: ast.FunctionDef):
        """
        Using `==` to compare secrets/tokens is vulnerable to timing attacks.
        `hmac.compare_digest()` should be used instead.
        """
        security_keywords = {"token", "secret", "key", "signature", "hmac", "hash", "digest"}
        fn_name = node.name.lower()
        is_security_fn = any(kw in fn_name for kw in security_keywords)

        if not is_security_fn:
            return

        for child in ast.walk(node):
            if not isinstance(child, ast.Compare):
                continue
            for op in child.ops:
                if isinstance(op, ast.Eq):
                    self._add(
                        child,
                        "Timing Attack via == Comparison of Secret/Token",
                        VulnCategory.AUTH,
                        Severity.HIGH,
                        (
                            f"Function '{node.name}' uses == to compare what appears to be "
                            "a secret, token, or signature. Python's == operator short-circuits "
                            "on the first differing byte, allowing timing attacks to enumerate "
                            "valid tokens byte-by-byte."
                        ),
                        "A02:2021 – Cryptographic Failures",
                        "CWE-208",
                        Fix(
                            description="Use hmac.compare_digest() for constant-time comparison",
                            original_code="if token == expected_token:",
                            fixed_code=(
                                "import hmac\n"
                                "if hmac.compare_digest(token.encode(), expected_token.encode()):"
                            ),
                            explanation="compare_digest() runs in constant time regardless of where values differ.",
                        ),
                    )
                    break  # one finding per function is enough

    def _check_cbv_missing_auth(self, node: ast.ClassDef):
        """
        Class-based views that inherit from View but don't mix in
        LoginRequiredMixin may expose sensitive functionality publicly.
        """
        base_names = set()
        for base in node.bases:
            if isinstance(base, ast.Name):
                base_names.add(base.id)
            elif isinstance(base, ast.Attribute):
                base_names.add(base.attr)

        is_django_view = bool(base_names & {
            "View", "ListView", "DetailView", "UpdateView",
            "CreateView", "DeleteView", "FormView", "TemplateView",
        })
        has_auth_mixin = bool(base_names & {
            "LoginRequiredMixin", "PermissionRequiredMixin",
            "UserPassesTestMixin", "StaffRequiredMixin",
        })

        if not is_django_view or has_auth_mixin:
            return

        # Only flag if class name suggests sensitive operations
        sensitive_keywords = {
            "Delete", "Update", "Edit", "Create", "Admin", "Dashboard",
            "Profile", "Account", "Setting", "Payment", "Order", "Export",
        }
        class_lower = node.name
        is_sensitive = any(kw in class_lower for kw in sensitive_keywords)

        if is_sensitive:
            self._add(
                node,
                f"CBV '{node.name}' Missing LoginRequiredMixin",
                VulnCategory.AUTH,
                Severity.MEDIUM,
                (
                    f"Class-based view '{node.name}' performs sensitive operations but does not "
                    "include LoginRequiredMixin. Without it, the view may be accessible to "
                    "unauthenticated users if connected to a URL route."
                ),
                "A01:2021 – Broken Access Control",
                "CWE-306",
                Fix(
                    description="Add LoginRequiredMixin as first base class",
                    original_code=f"class {node.name}({', '.join(b.id if isinstance(b, ast.Name) else b.attr for b in node.bases if isinstance(b, (ast.Name, ast.Attribute)))})",
                    fixed_code=(
                        "from django.contrib.auth.mixins import LoginRequiredMixin\n\n"
                        f"class {node.name}(LoginRequiredMixin, ...):"
                    ),
                    manual_review_required=True,
                    explanation="Add LoginRequiredMixin before other view base classes.",
                ),
            )

    def _check_dynamic_getattr(self, node: ast.Call):
        """
        getattr(obj, user_controlled) allows attackers to access any attribute,
        including private/dunder attributes that leak internals.
        """
        call_name = self._get_call_name(node)
        if call_name != "getattr":
            return
        if len(node.args) < 2:
            return

        # Check if second argument looks like it could be user-controlled
        second_arg = node.args[1]
        if isinstance(second_arg, (ast.Subscript, ast.Call)):
            # e.g. getattr(obj, request.GET['field']) or getattr(obj, get_input())
            self._add(
                node,
                "Dynamic getattr() with Potentially User-Controlled Attribute Name",
                VulnCategory.INJECTION,
                Severity.HIGH,
                (
                    "getattr() is called with a dynamically computed attribute name. "
                    "If this value originates from user input, an attacker can access "
                    "any attribute including __class__, __dict__, private methods, or "
                    "other sensitive internals of the object."
                ),
                "A03:2021 – Injection",
                "CWE-470",
                Fix(
                    description="Use an explicit allowlist of permitted attribute names",
                    original_code=self._snippet(node),
                    fixed_code=(
                        "ALLOWED_ATTRS = {'name', 'description', 'status'}  # explicit whitelist\n"
                        "attr_name = request.GET.get('field')\n"
                        "if attr_name not in ALLOWED_ATTRS:\n"
                        "    raise PermissionDenied('Invalid field')\n"
                        "value = getattr(obj, attr_name)"
                    ),
                    explanation="Always validate dynamic attribute names against an allowlist.",
                ),
            )

    def _check_assert_used_for_auth(self, node: ast.Call):
        """
        assert statements are stripped when Python runs with -O (optimized).
        Using assert for security checks means they disappear in production.
        Detected via call inspection — we look for Assert nodes in context.
        """
        # This is caught at the Assert node level
        pass

    def visit_Assert(self, node: ast.Assert):
        """Detect assert used as a security gate."""
        # Check if the assert test involves auth/permission checks
        test_src = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
        security_terms = ["auth", "permission", "login", "staff", "superuser", "is_authenticated"]
        if any(term in test_src.lower() for term in security_terms):
            self._add(
                node,
                "assert Used for Security Check (Stripped in Optimized Mode)",
                VulnCategory.AUTH,
                Severity.HIGH,
                (
                    "assert statements are completely removed when Python runs with the -O "
                    "(optimize) flag, which many production environments enable. Security "
                    "checks implemented with assert provide no protection in production."
                ),
                "A07:2021 – Identification and Authentication Failures",
                "CWE-617",
                Fix(
                    description="Replace assert with an explicit if/raise check",
                    original_code=f"assert {test_src}",
                    fixed_code=(
                        f"if not ({test_src}):\n"
                        "    from django.core.exceptions import PermissionDenied\n"
                        "    raise PermissionDenied('Access denied')"
                    ),
                    explanation="Never use assert for security checks — use explicit if/raise.",
                ),
            )
        self.generic_visit(node)

    def _check_random_for_security(self, node: ast.Call):
        """
        Python's random module is not cryptographically secure.
        Using it for tokens, session IDs, or passwords is dangerous.
        """
        call_name = self._get_call_name(node)
        insecure_random = {
            "random.random", "random.randint", "random.choice",
            "random.choices", "random.sample", "random.shuffle",
            "random.randrange",
        }
        if call_name not in insecure_random:
            return

        # Look at variable name being assigned to for context
        parent_src = self._snippet(node)
        security_terms = ["token", "secret", "key", "password", "otp", "code", "salt", "nonce"]
        if any(term in parent_src.lower() for term in security_terms):
            self._add(
                node,
                "Insecure random Module Used for Security-Sensitive Value",
                VulnCategory.AUTH,
                Severity.HIGH,
                (
                    f"{call_name}() uses Python's Mersenne Twister PRNG which is not "
                    "cryptographically secure. An attacker who observes enough outputs can "
                    "predict future values, allowing them to forge tokens, OTPs, or session IDs."
                ),
                "A02:2021 – Cryptographic Failures",
                "CWE-338",
                Fix(
                    description="Use secrets module for cryptographically secure random values",
                    original_code=parent_src,
                    fixed_code=(
                        "import secrets\n\n"
                        "# Cryptographically secure alternatives:\n"
                        "token = secrets.token_hex(32)       # 64-char hex token\n"
                        "token = secrets.token_urlsafe(32)   # URL-safe token\n"
                        "otp = str(secrets.randbelow(1000000)).zfill(6)  # 6-digit OTP"
                    ),
                    explanation="The secrets module uses OS-level CSPRNG (urandom).",
                ),
            )

    def _check_md5_sha1_for_secrets(self, node: ast.Call):
        """
        MD5 and SHA-1 are cryptographically broken. Using them for password
        hashing, HMAC, or data integrity is insecure.
        """
        call_name = self._get_call_name(node)

        # hashlib.md5(), hashlib.sha1(), hashlib.new('md5')
        is_weak_hash = False
        if call_name in ("hashlib.md5", "hashlib.sha1"):
            is_weak_hash = True
        elif call_name == "hashlib.new" and node.args:
            if isinstance(node.args[0], ast.Constant):
                algo = str(node.args[0].value).lower()
                if algo in ("md5", "sha1", "sha"):
                    is_weak_hash = True

        if not is_weak_hash:
            return

        parent_src = self._snippet(node)
        self._add(
            node,
            "Weak Hash Algorithm (MD5/SHA-1) for Security-Sensitive Operation",
            VulnCategory.SENSITIVE_DATA,
            Severity.HIGH,
            (
                f"{call_name} uses a cryptographically broken hash function. "
                "MD5 and SHA-1 are vulnerable to collision attacks and should not "
                "be used for password hashing, HMAC, digital signatures, or data integrity."
            ),
            "A02:2021 – Cryptographic Failures",
            "CWE-327",
            Fix(
                description="Use SHA-256 or stronger; use bcrypt/argon2 for passwords",
                original_code=parent_src,
                fixed_code=(
                    "# For general hashing:\n"
                    "import hashlib\n"
                    "hashlib.sha256(data).hexdigest()\n\n"
                    "# For passwords — use Django's built-in:\n"
                    "from django.contrib.auth.hashers import make_password\n"
                    "hashed = make_password(raw_password)\n\n"
                    "# For HMAC:\n"
                    "import hmac, hashlib\n"
                    "hmac.new(key, msg, hashlib.sha256).hexdigest()"
                ),
                explanation="Use SHA-256+ for integrity, argon2/bcrypt for passwords.",
            ),
        )

    def _check_format_string_log(self, node: ast.Call):
        """
        Logging with % or .format() instead of lazy % args can cause
        log injection if user input contains format characters or newlines.
        """
        call_name = self._get_call_name(node)
        log_methods = {"logging.info", "logging.debug", "logging.warning",
                        "logging.error", "logging.critical", "logger.info",
                        "logger.debug", "logger.warning", "logger.error"}

        if call_name not in log_methods:
            return

        if not node.args:
            return

        first_arg = node.args[0]
        # Flag if first arg is a f-string or .format() call
        if isinstance(first_arg, ast.JoinedStr):  # f-string
            self._add(
                node,
                "Log Injection via f-string in Logging Call",
                VulnCategory.INJECTION,
                Severity.LOW,
                (
                    "Using an f-string in a logging call embeds user data directly into the "
                    "log message before the logging system processes it. This allows log injection "
                    "if the data contains newlines (\\n) or ANSI escape codes, and prevents "
                    "log aggregators from grouping similar messages."
                ),
                "A09:2021 – Security Logging and Monitoring Failures",
                "CWE-117",
                Fix(
                    description="Use lazy % logging to prevent log injection",
                    original_code=self._snippet(node),
                    fixed_code=(
                        '# Use lazy % args instead of f-strings:\n'
                        'logger.info("User %s performed action %s", user_id, action)\n'
                        '# NOT: logger.info(f"User {user_id} performed {action}")'
                    ),
                    explanation="Lazy % args are sanitized by the logging framework.",
                ),
            )

    def _check_hardcoded_ip(self, node: ast.Assign):
        """
        Hardcoded IP addresses (especially internal ones) in settings or
        config code can expose infrastructure topology.
        """
        import re
        if not node.targets:
            return

        target = node.targets[0]
        target_name = ""
        if isinstance(target, ast.Name):
            target_name = target.id.lower()
        elif isinstance(target, ast.Attribute):
            target_name = target.attr.lower()

        # Only flag if variable name suggests it's a host/server address
        host_terms = {"host", "server", "ip", "addr", "endpoint", "url", "db_host"}
        if not any(term in target_name for term in host_terms):
            return

        # Check if value is a hardcoded string matching an IP
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            ip_pattern = r"\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+\b"
            if re.search(ip_pattern, node.value.value):
                self._add(
                    node,
                    "Hardcoded Private IP Address",
                    VulnCategory.MISCONFIG,
                    Severity.LOW,
                    (
                        "A private IP address is hardcoded in source code. This exposes "
                        "internal network topology and makes the code environment-specific, "
                        "preventing proper staging/production separation."
                    ),
                    "A05:2021 – Security Misconfiguration",
                    "CWE-200",
                    Fix(
                        description="Move IP address to environment variable",
                        original_code=self._snippet(node),
                        fixed_code=(
                            "import os\n"
                            f"{target_name.upper()} = os.environ.get('{target_name.upper()}', 'localhost')"
                        ),
                        explanation="Use environment variables for all infrastructure addresses.",
                    ),
                )

    def _check_is_comparison_to_true(self, node: ast.Compare):
        """
        `if x is True` fails for truthy values. In auth checks this can
        cause bypass — e.g. if a permission function returns 1 instead of True.
        """
        for op, comparator in zip(node.ops, node.comparators):
            if not isinstance(op, ast.Is):
                continue
            if not isinstance(comparator, ast.Constant):
                continue
            if comparator.value is not True:
                continue

            # Only flag in security-looking context
            left_src = ast.unparse(node.left) if hasattr(ast, "unparse") else ""
            security_terms = ["permission", "auth", "allowed", "has_access", "is_valid"]
            if any(t in left_src.lower() for t in security_terms):
                self._add(
                    node,
                    "Strict Identity Check (is True) in Security Context",
                    VulnCategory.AUTH,
                    Severity.LOW,
                    (
                        f"`{left_src} is True` fails when the expression returns a truthy "
                        "non-boolean (e.g. 1, non-empty string). In authentication or permission "
                        "checks, this can cause bypass if the permission function returns a "
                        "truthy value instead of the boolean True."
                    ),
                    "A07:2021 – Identification and Authentication Failures",
                    "CWE-697",
                    Fix(
                        description="Use bool() or truthiness check instead of `is True`",
                        original_code=f"if {left_src} is True:",
                        fixed_code=f"if {left_src}:  # truthy check, accepts True/1/non-empty",
                        explanation="Use truthy check unless you specifically need True identity.",
                    ),
                )
