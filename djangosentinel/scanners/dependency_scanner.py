"""
Vulnerable Dependency Scanner.
Checks requirements.txt, Pipfile, pyproject.toml, and setup.py against
known vulnerable package versions. Includes a built-in CVE database
for the most critical Django ecosystem vulnerabilities.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import uuid

try:
    from packaging import version as pkg_version
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False

from djangosentinel.models import (
    Vulnerability, VulnCategory, Severity, CodeLocation, Fix
)


# Built-in CVE database for critical Django ecosystem packages
# Format: package -> [(affected_range, fixed_version, cve, severity, description)]
VULN_DATABASE: Dict[str, List[Dict]] = {
    "django": [
        {
            "affected_below": "3.2.21",
            "affected_above": "3.2.0",
            "fixed": "3.2.21",
            "cve": "CVE-2023-41164",
            "severity": Severity.HIGH,
            "title": "Django Potential Denial of Service via Email Validator",
            "description": "Very long email addresses in EmailValidator cause catastrophic backtracking in regex.",
        },
        {
            "affected_below": "4.2.7",
            "affected_above": "4.2.0",
            "fixed": "4.2.7",
            "cve": "CVE-2023-46695",
            "severity": Severity.HIGH,
            "title": "Django Username Enumeration via Timing Attack",
            "description": "Timing attack in UsernameField allows username enumeration via response time differences.",
        },
        {
            "affected_below": "4.2.1",
            "affected_above": "4.0.0",
            "fixed": "4.2.1",
            "cve": "CVE-2023-31047",
            "severity": Severity.CRITICAL,
            "title": "Django File Upload Bypass via Crafted Filename",
            "description": "Uploaded files with certain filenames bypass extension validation.",
        },
        {
            "affected_below": "3.2.0",
            "affected_above": "0.0.0",
            "fixed": "3.2.0",
            "cve": "CVE-2021-28658",
            "severity": Severity.HIGH,
            "title": "Django Path Traversal in FileSystemStorage",
            "description": "FileSystemStorage is vulnerable to path traversal in certain configurations.",
        },
    ],
    "djangorestframework": [
        {
            "affected_below": "3.14.0",
            "affected_above": "0.0.0",
            "fixed": "3.14.0",
            "cve": "CVE-2023-28021",
            "severity": Severity.HIGH,
            "title": "DRF Authentication Bypass via Malformed Token",
            "description": "Certain malformed tokens can bypass authentication in DRF token views.",
        },
    ],
    "pillow": [
        {
            "affected_below": "10.0.0",
            "affected_above": "0.0.0",
            "fixed": "10.0.0",
            "cve": "CVE-2023-44271",
            "severity": Severity.HIGH,
            "title": "Pillow Uncontrolled Resource Consumption via Crafted Image",
            "description": "Specially crafted images can cause excessive memory consumption leading to DoS.",
        },
        {
            "affected_below": "9.3.0",
            "affected_above": "0.0.0",
            "fixed": "9.3.0",
            "cve": "CVE-2022-45199",
            "severity": Severity.HIGH,
            "title": "Pillow DoS via Decompression Bomb",
            "description": "Pillow is vulnerable to decompression bomb attacks in certain image formats.",
        },
    ],
    "requests": [
        {
            "affected_below": "2.31.0",
            "affected_above": "0.0.0",
            "fixed": "2.31.0",
            "cve": "CVE-2023-32681",
            "severity": Severity.MEDIUM,
            "title": "Requests Proxy-Authorization Header Leak",
            "description": "Proxy-Authorization header is forwarded to destination server on redirect.",
        },
    ],
    "cryptography": [
        {
            "affected_below": "41.0.0",
            "affected_above": "0.0.0",
            "fixed": "41.0.0",
            "cve": "CVE-2023-38325",
            "severity": Severity.HIGH,
            "title": "Cryptography SSH Certificate Invalid Policy",
            "description": "Parsing malformed SSH certificates can cause incorrect signature validation.",
        },
    ],
    "pyyaml": [
        {
            "affected_below": "6.0.0",
            "affected_above": "0.0.0",
            "fixed": "6.0.0",
            "cve": "CVE-2020-14343",
            "severity": Severity.CRITICAL,
            "title": "PyYAML Unsafe Deserialization (yaml.load)",
            "description": "PyYAML yaml.load() without Loader allows arbitrary code execution.",
        },
    ],
    "jinja2": [
        {
            "affected_below": "3.1.3",
            "affected_above": "0.0.0",
            "fixed": "3.1.3",
            "cve": "CVE-2024-22195",
            "severity": Severity.MEDIUM,
            "title": "Jinja2 XSS via xmlattr Filter",
            "description": "The xmlattr filter does not properly escape attribute names, enabling XSS.",
        },
    ],
    "werkzeug": [
        {
            "affected_below": "2.3.8",
            "affected_above": "0.0.0",
            "fixed": "2.3.8",
            "cve": "CVE-2023-46136",
            "severity": Severity.HIGH,
            "title": "Werkzeug Multipart Data Parsing DoS",
            "description": "Specially crafted multipart data can cause a DoS in Werkzeug's parser.",
        },
    ],
    "sqlalchemy": [
        {
            "affected_below": "2.0.0",
            "affected_above": "0.0.0",
            "fixed": "2.0.0",
            "cve": "CVE-2019-7164",
            "severity": Severity.HIGH,
            "title": "SQLAlchemy SQL Injection via order_by",
            "description": "User input passed to order_by() may allow SQL injection in certain dialects.",
        },
    ],
    "celery": [
        {
            "affected_below": "5.2.2",
            "affected_above": "0.0.0",
            "fixed": "5.2.2",
            "cve": "CVE-2021-23727",
            "severity": Severity.HIGH,
            "title": "Celery Command Injection via Task Serialization",
            "description": "Celery workers using pickle serialization are vulnerable to RCE via crafted messages.",
        },
    ],
    "paramiko": [
        {
            "affected_below": "3.4.0",
            "affected_above": "0.0.0",
            "fixed": "3.4.0",
            "cve": "CVE-2023-48795",
            "severity": Severity.MEDIUM,
            "title": "Paramiko SSH Terrapin Attack Vulnerability",
            "description": "Paramiko is affected by the Terrapin attack on SSH protocol integrity.",
        },
    ],
    "urllib3": [
        {
            "affected_below": "1.26.17",
            "affected_above": "1.0.0",
            "fixed": "1.26.17",
            "cve": "CVE-2023-43804",
            "severity": Severity.MEDIUM,
            "title": "urllib3 Cookie Header Leakage on Redirect",
            "description": "Cookie headers are incorrectly forwarded to third-party servers on redirect.",
        },
    ],
}

# Dangerous packages that should trigger warnings regardless of version
DANGEROUS_PACKAGES = {
    "pickle": "Pickle deserialization executes arbitrary code. Use JSON or MessagePack instead.",
    "marshal": "Marshal deserialization is unsafe with untrusted data.",
    "shelve": "Shelve uses pickle internally and is unsafe with untrusted data.",
    "xml.etree.ElementTree": "xml.etree.ElementTree is vulnerable to XML bomb attacks. Use defusedxml.",
    "xmlrpc": "XML-RPC is prone to XXE and SSRF. Consider REST/JSON APIs.",
}


class DependencyScanner:
    """Scans Python dependency files for known vulnerable packages."""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.vulnerabilities: List[Vulnerability] = []

    def scan(self) -> List[Vulnerability]:
        self.vulnerabilities = []

        dep_files = [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements/base.txt",
            "requirements/production.txt",
            "requirements/common.txt",
            "Pipfile",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
        ]

        for dep_file in dep_files:
            full_path = self.project_path / dep_file
            if full_path.exists():
                try:
                    self._scan_requirements_file(full_path)
                except Exception:
                    continue

        # Scan Python files for dangerous module imports
        for py_file in self.project_path.rglob("*.py"):
            if self._is_excluded(py_file):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(py_file.relative_to(self.project_path))
                self._scan_dangerous_imports(source, rel_path)
            except Exception:
                continue

        return self.vulnerabilities

    def _is_excluded(self, path: Path) -> bool:
        excludes = {"venv", ".venv", "env", "node_modules", "__pycache__", ".git"}
        return any(part in excludes for part in path.parts)

    def _scan_requirements_file(self, req_file: Path):
        rel_path = str(req_file.relative_to(self.project_path))
        content = req_file.read_text(encoding="utf-8", errors="ignore")
        packages = self._parse_requirements(content, req_file.name)

        for line_num, package_name, package_version in packages:
            normalized = package_name.lower().replace("-", "").replace("_", "")
            for db_pkg, vulns in VULN_DATABASE.items():
                db_normalized = db_pkg.lower().replace("-", "").replace("_", "")
                if normalized == db_normalized and package_version:
                    for vuln in vulns:
                        if self._is_version_affected(package_version, vuln):
                            self.vulnerabilities.append(Vulnerability(
                                vuln_id=str(uuid.uuid4())[:8],
                                title=vuln["title"],
                                category=VulnCategory.INSECURE_DEPS,
                                severity=vuln["severity"],
                                location=CodeLocation(
                                    rel_path, line_num,
                                    snippet=f"{package_name}=={package_version}"
                                ),
                                description=vuln["description"],
                                owasp_ref="A06:2021 – Vulnerable and Outdated Components",
                                cve_id=vuln["cve"],
                                cwe_id="CWE-1035",
                                fix=Fix(
                                    description=f"Upgrade {package_name} to >={vuln['fixed']}",
                                    original_code=f"{package_name}=={package_version}",
                                    fixed_code=f"{package_name}>={vuln['fixed']}",
                                    explanation=(
                                        f"Version {package_version} of {package_name} is vulnerable "
                                        f"to {vuln['cve']}. Upgrade to {vuln['fixed']} or later."
                                    ),
                                ),
                                references=[
                                    f"https://nvd.nist.gov/vuln/detail/{vuln['cve']}",
                                    f"https://pypi.org/project/{package_name}/{vuln['fixed']}/",
                                ],
                            ))

    def _parse_requirements(
        self, content: str, filename: str
    ) -> List[Tuple[int, str, Optional[str]]]:
        """Parse requirements file and return (line_num, package, version) tuples."""
        results = []
        lines = content.splitlines()

        if filename == "Pipfile":
            in_packages = False
            for i, line in enumerate(lines, 1):
                if re.match(r'\[(?:packages|dev-packages)\]', line):
                    in_packages = True
                elif line.startswith('['):
                    in_packages = False
                elif in_packages:
                    m = re.match(r'(\S+)\s*=\s*["\']?([>=<!\d\.\*]+)["\']?', line)
                    if m:
                        results.append((i, m.group(1), m.group(2).strip('=').strip('*').strip()))
            return results

        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            # Match: package==1.2.3 or package>=1.2.3 etc.
            m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*[=><!\^~]+\s*([\d\.]+)', line)
            if m:
                results.append((i, m.group(1), m.group(2)))
            else:
                # Package without version pin
                m2 = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
                if m2:
                    results.append((i, m2.group(1), None))

        return results

    def _is_version_affected(self, installed: str, vuln: Dict) -> bool:
        """Check if installed version falls in the affected range."""
        if not HAS_PACKAGING:
            # Fallback: simple string comparison
            return installed < vuln["fixed"]
        try:
            iv = pkg_version.parse(installed)
            above = pkg_version.parse(vuln["affected_above"])
            below = pkg_version.parse(vuln["affected_below"])
            return above <= iv < below
        except Exception:
            return False

    def _scan_dangerous_imports(self, source: str, file_path: str):
        """Detect imports of inherently dangerous modules."""
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            for pkg, warning in DANGEROUS_PACKAGES.items():
                if re.search(rf'\bimport\s+{re.escape(pkg)}\b|from\s+{re.escape(pkg)}\b', line):
                    self.vulnerabilities.append(Vulnerability(
                        vuln_id=str(uuid.uuid4())[:8],
                        title=f"Dangerous Module Import: {pkg}",
                        category=VulnCategory.INSECURE_DEPS,
                        severity=Severity.HIGH,
                        location=CodeLocation(file_path, i, snippet=line.strip()),
                        description=warning,
                        owasp_ref="A06:2021 – Vulnerable and Outdated Components",
                        cwe_id="CWE-502",
                        fix=Fix(
                            description=f"Replace {pkg} with safe alternative",
                            original_code=line.strip(),
                            fixed_code=(
                                "# For serialization: use json or msgpack\n"
                                "import json\n"
                                "data = json.dumps(obj)  # Safe serialization\n"
                                "obj = json.loads(data)  # Safe deserialization\n\n"
                                "# For XML: use defusedxml\n"
                                "# pip install defusedxml\n"
                                "import defusedxml.ElementTree as ET"
                            ),
                            manual_review_required=True,
                            explanation=warning,
                        ),
                    ))
