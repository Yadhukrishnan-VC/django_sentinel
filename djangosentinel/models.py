"""
Core data models for vulnerability representation.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
import json


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnCategory(Enum):
    INJECTION = "SQL/Command Injection"
    XSS = "Cross-Site Scripting (XSS)"
    CSRF = "Cross-Site Request Forgery"
    AUTH = "Authentication & Authorization"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    MISCONFIG = "Security Misconfiguration"
    INSECURE_DEPS = "Insecure Dependencies"
    BUSINESS_LOGIC = "Business Logic Vulnerability"
    IDOR = "Insecure Direct Object Reference"
    SSRF = "Server-Side Request Forgery"
    XXE = "XML External Entity"
    OPEN_REDIRECT = "Open Redirect"
    RACE_CONDITION = "Race Condition"
    MASS_ASSIGNMENT = "Mass Assignment"
    HARDCODED_SECRET = "Hardcoded Secret/Credential"


@dataclass
class CodeLocation:
    file_path: str
    line_number: int
    column: Optional[int] = None
    end_line: Optional[int] = None
    snippet: Optional[str] = None

    def __str__(self):
        col = f":{self.column}" if self.column else ""
        return f"{self.file_path}:{self.line_number}{col}"


@dataclass
class Fix:
    description: str
    original_code: str
    fixed_code: str
    applied: bool = False
    manual_review_required: bool = False
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "original_code": self.original_code,
            "fixed_code": self.fixed_code,
            "applied": self.applied,
            "manual_review_required": self.manual_review_required,
            "explanation": self.explanation,
        }


@dataclass
class Vulnerability:
    vuln_id: str
    title: str
    category: VulnCategory
    severity: Severity
    location: CodeLocation
    description: str
    owasp_ref: str = ""
    cwe_id: str = ""
    cve_id: str = ""
    fix: Optional[Fix] = None
    false_positive: bool = False
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def confidence(self) -> Optional[float]:
        """Confidence score (0.0-1.0). Set by apply_confidence_scores()."""
        return self.metadata.get("confidence")

    @property
    def confidence_label(self) -> str:
        """Human-readable confidence label: HIGH / MEDIUM / LOW / UNCERTAIN."""
        return self.metadata.get("confidence_label", "UNCERTAIN")

    @property
    def is_taint_detected(self) -> bool:
        """True if this finding was confirmed by data-flow taint analysis."""
        return self.metadata.get("source") == "taint_tracker"

    @property
    def is_ai_detected(self) -> bool:
        """True if this finding was detected by the AI pattern scanner."""
        return self.metadata.get("source") == "ai_pattern_scanner"

    @property
    def is_ast_detected(self) -> bool:
        """True if this finding was detected by AST structural analysis."""
        return bool(self.metadata.get("ast_detected")) or self.metadata.get("source") == "ast_scanner"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.vuln_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "location": {
                "file": self.location.file_path,
                "line": self.location.line_number,
                "snippet": self.location.snippet,
            },
            "description": self.description,
            "owasp": self.owasp_ref,
            "cwe": self.cwe_id,
            "cve": self.cve_id,
            "fix_available": self.fix is not None,
            "fix_applied": self.fix.applied if self.fix else False,
            "references": self.references,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class ScanResult:
    scan_id: str
    project_path: str
    files_scanned: int
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)

    @property
    def fixable_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.fix is not None)

    @property
    def fixed_count(self) -> int:
        return sum(
            1
            for v in self.vulnerabilities
            if v.fix is not None and v.fix.applied
        )

    def summary(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "project": self.project_path,
            "files_scanned": self.files_scanned,
            "total_vulnerabilities": len(self.vulnerabilities),
            "by_severity": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "fixable": self.fixable_count,
            "fixed": self.fixed_count,
            "duration_seconds": self.scan_duration_seconds,
        }
