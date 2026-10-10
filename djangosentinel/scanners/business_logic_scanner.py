"""
Business Logic Vulnerability Scanner.
Detects flaws in application logic that security tools typically miss:
- Race conditions in financial operations
- Negative value manipulation
- Privilege escalation paths
- Workflow bypass opportunities
- Coupon/discount abuse patterns
- Quantity/price manipulation
"""

import re
import ast
from pathlib import Path
from typing import List
import uuid

from djangosentinel.models import (
    Vulnerability, VulnCategory, Severity, CodeLocation, Fix
)


class BusinessLogicScanner:
    """
    Detects business logic vulnerabilities that automated scanners miss.
    These flaws exist in application-specific logic, not generic patterns.
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
                self._scan_race_conditions(source, rel_path)
                self._scan_financial_operations(source, rel_path)
                self._scan_privilege_escalation(source, rel_path)
                self._scan_workflow_bypass(source, rel_path)
                self._scan_negative_values(source, rel_path)
                self._scan_coupon_abuse(source, rel_path)
                self._scan_pagination_disclosure(source, rel_path)
                self._scan_time_based_logic(source, rel_path)
            except Exception:
                continue
        return self.vulnerabilities

    def _is_excluded(self, path: Path) -> bool:
        excludes = {"venv", ".venv", "env", "node_modules", "__pycache__", ".git", "migrations"}
        return any(part in excludes for part in path.parts)

    def _scan_race_conditions(self, source: str, file_path: str):
        """Detect race conditions in balance checks and inventory management."""
        lines = source.splitlines()

        # Detect check-then-act without atomic transaction
        check_act_pattern = re.compile(
            r'(balance|stock|inventory|quantity|credits?|tokens?)\s*>=?\s*\d+',
            re.IGNORECASE,
        )
        atomic_pattern = re.compile(r'atomic|select_for_update|F\(', re.IGNORECASE)

        for i, line in enumerate(lines, 1):
            if check_act_pattern.search(line):
                # Look ahead 5 lines for atomic protection
                context = "\n".join(lines[max(0, i - 3) : i + 5])
                if not atomic_pattern.search(context):
                    self.vulnerabilities.append(Vulnerability(
                        vuln_id=str(uuid.uuid4())[:8],
                        title="Race Condition in Balance/Inventory Check",
                        category=VulnCategory.RACE_CONDITION,
                        severity=Severity.HIGH,
                        location=CodeLocation(file_path, i, snippet=line.strip()),
                        description=(
                            "Balance or inventory check without atomic transaction is "
                            "vulnerable to TOCTOU (Time-of-Check to Time-of-Use) race "
                            "conditions. Concurrent requests can pass the check and "
                            "overdraft accounts or oversell inventory."
                        ),
                        owasp_ref="A04:2021 – Insecure Design",
                        cwe_id="CWE-362",
                        fix=Fix(
                            description="Wrap in atomic transaction with select_for_update",
                            original_code=line.strip(),
                            fixed_code=(
                                "from django.db import transaction\n\n"
                                "with transaction.atomic():\n"
                                "    # Lock the row for the duration of the transaction\n"
                                "    account = Account.objects.select_for_update().get(pk=account_id)\n"
                                "    if account.balance >= amount:\n"
                                "        account.balance -= amount\n"
                                "        account.save()\n"
                                "    else:\n"
                                "        raise InsufficientFundsError()"
                            ),
                            explanation=(
                                "select_for_update() acquires a database row lock, preventing "
                                "concurrent modifications until the transaction completes."
                            ),
                            manual_review_required=True,
                        ),
                        references=[
                            "https://docs.djangoproject.com/en/stable/ref/models/querysets/#select-for-update"
                        ],
                    ))

    def _scan_financial_operations(self, source: str, file_path: str):
        """Detect unsafe financial calculations."""
        lines = source.splitlines()

        float_currency_pattern = re.compile(
            r'(price|amount|total|balance|cost|fee|tax)\s*=\s*float\(',
            re.IGNORECASE,
        )

        for i, line in enumerate(lines, 1):
            # Float arithmetic for money
            if float_currency_pattern.search(line):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Floating-Point Arithmetic Used for Monetary Values",
                    category=VulnCategory.BUSINESS_LOGIC,
                    severity=Severity.MEDIUM,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "Floating-point numbers cannot represent decimal currency values "
                        "exactly. Operations like 0.1 + 0.2 = 0.30000000000000004 can "
                        "cause rounding errors in financial calculations, leading to "
                        "accounting discrepancies or exploitable precision bugs."
                    ),
                    owasp_ref="A04:2021 – Insecure Design",
                    cwe_id="CWE-681",
                    fix=Fix(
                        description="Use Python Decimal for monetary values",
                        original_code=line.strip(),
                        fixed_code=(
                            "from decimal import Decimal, ROUND_HALF_UP\n\n"
                            "# Use Decimal for all monetary calculations:\n"
                            "price = Decimal('19.99')\n"
                            "tax = price * Decimal('0.08')\n"
                            "total = (price + tax).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)\n\n"
                            "# In Django models:\n"
                            "# price = models.DecimalField(max_digits=10, decimal_places=2)"
                        ),
                        explanation="Python's Decimal type provides exact decimal arithmetic.",
                    ),
                ))

            # Detect negative price/amount not validated
            if re.search(r'(price|amount|quantity|qty)\s*=\s*(?:int|float)\s*\(\s*request\.(GET|POST)', line, re.IGNORECASE):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Negative Value Manipulation – Price/Quantity Not Validated",
                    category=VulnCategory.BUSINESS_LOGIC,
                    severity=Severity.HIGH,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "User-supplied price or quantity values accepted without "
                        "non-negative validation. Attackers can submit negative quantities "
                        "to increase their balance or receive refunds on purchases."
                    ),
                    owasp_ref="A04:2021 – Insecure Design",
                    cwe_id="CWE-20",
                    fix=Fix(
                        description="Validate that price/quantity is positive",
                        original_code=line.strip(),
                        fixed_code=(
                            "quantity = int(request.POST.get('quantity', 1))\n"
                            "if quantity <= 0:\n"
                            "    return HttpResponseBadRequest('Quantity must be positive')\n"
                            "# Never trust client-side prices; always look up server-side:\n"
                            "product = get_object_or_404(Product, pk=product_id)\n"
                            "total = product.price * quantity  # Use DB price, not request price"
                        ),
                        explanation="Always validate user-supplied numeric inputs server-side.",
                    ),
                ))

    def _scan_privilege_escalation(self, source: str, file_path: str):
        """Detect privilege escalation vulnerabilities."""
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            # Detect role/permission update from user input
            if re.search(
                r'(is_staff|is_superuser|role|permission|is_admin)\s*=\s*request\.(GET|POST|data)',
                line, re.IGNORECASE
            ):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Privilege Escalation via User-Controlled Role Field",
                    category=VulnCategory.AUTH,
                    severity=Severity.CRITICAL,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "A privileged field (is_staff, is_superuser, role) is being set "
                        "from user-supplied request data. This allows any user to escalate "
                        "their own privileges by crafting a malicious request."
                    ),
                    owasp_ref="A01:2021 – Broken Access Control",
                    cwe_id="CWE-269",
                    fix=Fix(
                        description="Remove privileged fields from user-controlled updates",
                        original_code=line.strip(),
                        fixed_code=(
                            "# NEVER set privileged fields from request data\n"
                            "# Use explicit admin-only views for role management:\n"
                            "@login_required\n"
                            "def update_profile(request):\n"
                            "    allowed_fields = ['first_name', 'last_name', 'bio']  # Whitelist\n"
                            "    for field in allowed_fields:\n"
                            "        if field in request.POST:\n"
                            "            setattr(request.user, field, request.POST[field])\n"
                            "    request.user.save(update_fields=allowed_fields)"
                        ),
                        explanation="Whitelist updateable fields; never include privilege fields.",
                    ),
                ))

    def _scan_workflow_bypass(self, source: str, file_path: str):
        """Detect workflow state bypass vulnerabilities."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            # Detect direct status transitions without validation
            if re.search(
                r'status\s*=\s*["\'](?:approved|paid|completed|shipped|verified)["\']',
                line, re.IGNORECASE,
            ):
                context_before = "\n".join(lines[max(0, i - 5):i])
                if not re.search(r'if.*status|assert.*status|check.*status|permission|@login', context_before, re.IGNORECASE):
                    self.vulnerabilities.append(Vulnerability(
                        vuln_id=str(uuid.uuid4())[:8],
                        title="Workflow State Bypass – Direct Status Update Without Validation",
                        category=VulnCategory.BUSINESS_LOGIC,
                        severity=Severity.HIGH,
                        location=CodeLocation(file_path, i, snippet=line.strip()),
                        description=(
                            "Order or workflow status is set directly without verifying "
                            "the current state and valid transitions. Attackers may skip "
                            "required steps (e.g., mark unpaid orders as paid) by "
                            "accessing endpoints out of sequence."
                        ),
                        owasp_ref="A04:2021 – Insecure Design",
                        cwe_id="CWE-841",
                        fix=Fix(
                            description="Implement state machine with valid transition checks",
                            original_code=line.strip(),
                            fixed_code=(
                                "VALID_TRANSITIONS = {\n"
                                "    'pending': ['processing', 'cancelled'],\n"
                                "    'processing': ['shipped', 'cancelled'],\n"
                                "    'shipped': ['delivered'],\n"
                                "}\n\n"
                                "def transition_order(order, new_status, user):\n"
                                "    if new_status not in VALID_TRANSITIONS.get(order.status, []):\n"
                                "        raise ValueError(f'Invalid transition: {order.status} -> {new_status}')\n"
                                "    order.status = new_status\n"
                                "    order.save()"
                            ),
                            explanation="Enforce state machine transitions to prevent workflow bypass.",
                            manual_review_required=True,
                        ),
                    ))

    def _scan_negative_values(self, source: str, file_path: str):
        """Detect missing negative value validation in critical operations."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            if re.search(r'withdraw|debit|deduct|subtract.*balance|balance.*-=', line, re.IGNORECASE):
                context = "\n".join(lines[max(0, i - 3):i + 3])
                if not re.search(r'>?\s*0|positive|min_value|MinValueValidator', context):
                    self.vulnerabilities.append(Vulnerability(
                        vuln_id=str(uuid.uuid4())[:8],
                        title="Missing Negative Balance Guard in Financial Operation",
                        category=VulnCategory.BUSINESS_LOGIC,
                        severity=Severity.HIGH,
                        location=CodeLocation(file_path, i, snippet=line.strip()),
                        description=(
                            "A debit/withdrawal operation lacks a check preventing the "
                            "balance from going negative. Concurrent requests or repeated "
                            "calls may overdraft accounts beyond allowed limits."
                        ),
                        owasp_ref="A04:2021 – Insecure Design",
                        cwe_id="CWE-20",
                        fix=Fix(
                            description="Add balance guard with atomic transaction",
                            original_code=line.strip(),
                            fixed_code=(
                                "with transaction.atomic():\n"
                                "    account = Account.objects.select_for_update().get(pk=pk)\n"
                                "    if account.balance < amount:\n"
                                "        raise InsufficientFundsError('Balance would go negative')\n"
                                "    account.balance = F('balance') - amount\n"
                                "    account.save()"
                            ),
                            explanation="Use F() expressions to avoid race conditions in balance updates.",
                        ),
                    ))

    def _scan_coupon_abuse(self, source: str, file_path: str):
        """Detect coupon/discount abuse vulnerabilities."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            if re.search(r'coupon|discount|promo.*code|voucher', line, re.IGNORECASE):
                context = "\n".join(lines[max(0, i - 3):i + 5])
                if not re.search(r'used|redeemed|user.*coupon|coupon.*user|unique_together|one.*per', context, re.IGNORECASE):
                    self.vulnerabilities.append(Vulnerability(
                        vuln_id=str(uuid.uuid4())[:8],
                        title="Coupon/Promo Code Reuse Not Restricted Per User",
                        category=VulnCategory.BUSINESS_LOGIC,
                        severity=Severity.MEDIUM,
                        location=CodeLocation(file_path, i, snippet=line.strip()),
                        description=(
                            "Coupon or promo code usage does not appear to track per-user "
                            "redemption. Without per-user tracking, codes can be reused "
                            "indefinitely by the same user."
                        ),
                        owasp_ref="A04:2021 – Insecure Design",
                        cwe_id="CWE-837",
                        fix=Fix(
                            description="Track coupon usage per user",
                            original_code=line.strip(),
                            fixed_code=(
                                "# Model to track coupon usage:\n"
                                "class CouponUsage(models.Model):\n"
                                "    coupon = models.ForeignKey(Coupon, on_delete=models.CASCADE)\n"
                                "    user = models.ForeignKey(User, on_delete=models.CASCADE)\n"
                                "    used_at = models.DateTimeField(auto_now_add=True)\n\n"
                                "    class Meta:\n"
                                "        unique_together = ('coupon', 'user')  # One use per user\n\n"
                                "# Check before applying:\n"
                                "if CouponUsage.objects.filter(coupon=coupon, user=request.user).exists():\n"
                                "    raise ValidationError('Coupon already used')"
                            ),
                            explanation="Use unique_together constraint to enforce one-per-user coupon usage.",
                            manual_review_required=True,
                        ),
                    ))

    def _scan_pagination_disclosure(self, source: str, file_path: str):
        """Detect data disclosure through unprotected pagination."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            if re.search(r'Paginator\(|page_obj|paginate_queryset', line):
                context = "\n".join(lines[max(0, i - 5):i + 5])
                if not re.search(r'filter.*user|user.*filter|request\.user', context):
                    self.vulnerabilities.append(Vulnerability(
                        vuln_id=str(uuid.uuid4())[:8],
                        title="Paginated Queryset May Disclose Other Users' Data",
                        category=VulnCategory.IDOR,
                        severity=Severity.MEDIUM,
                        location=CodeLocation(file_path, i, snippet=line.strip()),
                        description=(
                            "A paginated queryset does not appear to be filtered by the "
                            "current user. If the queryset includes all records, users can "
                            "enumerate other users' data by iterating through pages."
                        ),
                        owasp_ref="A01:2021 – Broken Access Control",
                        cwe_id="CWE-200",
                        fix=Fix(
                            description="Filter queryset by current user before paginating",
                            original_code=line.strip(),
                            fixed_code=(
                                "# Always filter by the current user:\n"
                                "queryset = Order.objects.filter(user=request.user)\n"
                                "paginator = Paginator(queryset, 25)\n"
                                "page_obj = paginator.get_page(request.GET.get('page'))"
                            ),
                            explanation="Scope all querysets to the authenticated user's data.",
                            manual_review_required=True,
                        ),
                    ))

    def _scan_time_based_logic(self, source: str, file_path: str):
        """Detect time-based business logic vulnerabilities."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            # Token/link expiry using datetime.now() instead of timezone.now()
            if re.search(r'datetime\.now\(\)', line) and re.search(r'expir|token|link|reset|valid', line, re.IGNORECASE):
                self.vulnerabilities.append(Vulnerability(
                    vuln_id=str(uuid.uuid4())[:8],
                    title="Timezone-Naive Datetime Used for Token Expiry",
                    category=VulnCategory.AUTH,
                    severity=Severity.MEDIUM,
                    location=CodeLocation(file_path, i, snippet=line.strip()),
                    description=(
                        "datetime.now() returns a timezone-naive datetime. Comparing it "
                        "with timezone-aware datetimes (Django's default) causes TypeError "
                        "or incorrect expiry calculations, potentially allowing expired "
                        "tokens to remain valid."
                    ),
                    owasp_ref="A07:2021 – Identification and Authentication Failures",
                    cwe_id="CWE-613",
                    fix=Fix(
                        description="Use django.utils.timezone.now() instead",
                        original_code="datetime.now()",
                        fixed_code=(
                            "from django.utils import timezone\n\n"
                            "# Use timezone-aware now:\n"
                            "timezone.now()\n\n"
                            "# Example expiry check:\n"
                            "if token.created_at + timedelta(hours=24) < timezone.now():\n"
                            "    raise TokenExpiredError()"
                        ),
                        explanation="Always use timezone.now() in Django for consistent timezone-aware datetimes.",
                    ),
                ))
