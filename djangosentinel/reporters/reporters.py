"""
Multi-format reporters for vulnerability scan results.
Supports: terminal (colored), JSON, HTML, SARIF (GitHub Code Scanning).
"""

import json
import html
from datetime import datetime
from typing import List
from pathlib import Path

from djangosentinel.models import ScanResult, Vulnerability, Severity, VulnCategory


# ANSI color codes
COLORS = {
    "CRITICAL": "\033[91m",   # Red
    "HIGH":     "\033[33m",   # Yellow
    "MEDIUM":   "\033[93m",   # Bright Yellow
    "LOW":      "\033[94m",   # Blue
    "INFO":     "\033[96m",   # Cyan
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "GREEN":    "\033[92m",
    "DIM":      "\033[2m",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}


class TerminalReporter:
    """Colorized terminal output reporter."""

    def __init__(self, no_color: bool = False):
        self.no_color = no_color

    def c(self, color: str, text: str) -> str:
        if self.no_color:
            return text
        return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"

    def report(self, result: ScanResult) -> str:
        lines = []

        # Header
        lines.append("")
        lines.append(self.c("BOLD", "╔══════════════════════════════════════════════════╗"))
        lines.append(self.c("BOLD", "║       🛡️  DJANGO SENTINEL — SECURITY REPORT       ║"))
        lines.append(self.c("BOLD", "╚══════════════════════════════════════════════════╝"))
        lines.append("")

        # Summary
        summary = result.summary()
        lines.append(f"  Project:  {summary['project']}")
        lines.append(f"  Files:    {summary['files_scanned']} scanned")
        lines.append(f"  Duration: {summary['duration_seconds']:.2f}s")
        lines.append(f"  Scan ID:  {summary['scan_id']}")
        lines.append("")

        # Severity breakdown
        total = summary["total_vulnerabilities"]
        by_sev = summary["by_severity"]

        lines.append("  VULNERABILITY SUMMARY")
        lines.append("  " + "─" * 40)
        lines.append(f"  {self.c('CRITICAL', '🔴 CRITICAL')}   {by_sev['critical']:>4}")
        lines.append(f"  {self.c('HIGH',     '🟠 HIGH')}       {by_sev['high']:>4}")
        lines.append(f"  {self.c('MEDIUM',   '🟡 MEDIUM')}     {by_sev['medium']:>4}")
        lines.append(f"  {self.c('LOW',      '🔵 LOW')}        {by_sev['low']:>4}")
        lines.append(f"  {'─' * 18}  ────")
        lines.append(f"  {'TOTAL':18}  {total:>4}")
        lines.append("")
        lines.append(f"  Auto-fixable: {self.c('GREEN', str(summary['fixable']))}")
        lines.append(f"  Fixed:        {self.c('GREEN', str(summary['fixed']))}")
        lines.append("")

        if not result.vulnerabilities:
            lines.append(self.c("GREEN", "  ✅ No vulnerabilities found!"))
            lines.append("")
            return "\n".join(lines)

        # Group by severity
        by_severity = {}
        for v in result.vulnerabilities:
            by_severity.setdefault(v.severity, []).append(v)

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            vulns = by_severity.get(severity, [])
            if not vulns:
                continue

            icon = SEVERITY_ICONS[severity]
            color = severity.value
            lines.append(f"  {self.c(color, f'{icon} {severity.value} ({len(vulns)})')}")
            lines.append("  " + "─" * 60)

            for v in vulns:
                status = ""
                if v.fix and v.fix.applied:
                    status = self.c("GREEN", " ✅ FIXED")
                elif v.fix and v.fix.manual_review_required:
                    status = self.c("MEDIUM", " ⚠️  MANUAL")
                elif v.fix:
                    status = self.c("GREEN", " 🔧 FIXABLE")

                lines.append(f"  {self.c('BOLD', v.title)}{status}")
                lines.append(f"  {self.c('DIM', f'  ID: {v.vuln_id} | CWE: {v.cwe_id} | {v.owasp_ref}')}")
                lines.append(f"  {self.c('DIM', f'  📍 {v.location}')}")

                if v.location.snippet and "[REDACTED]" not in v.location.snippet:
                    lines.append(f"  {self.c('DIM', f'  Code: {v.location.snippet[:80]}')}")

                lines.append(f"  {v.description[:120]}")

                if v.fix and not v.fix.applied:
                    lines.append(f"  {self.c('GREEN', '  💊 Fix: ' + v.fix.description)}")
                    if v.fix.manual_review_required:
                        lines.append(f"  {self.c('MEDIUM', '     ⚠️  Requires manual review')}")

                lines.append("")

        return "\n".join(lines)


class JSONReporter:
    """Machine-readable JSON reporter."""

    def report(self, result: ScanResult) -> str:
        output = {
            "sentinel_version": "1.0.0",
            "generated_at": datetime.now().isoformat(),
            "summary": result.summary(),
            "vulnerabilities": [v.to_dict() for v in result.vulnerabilities],
            "errors": result.errors,
        }
        return json.dumps(output, indent=2, default=str)


class HTMLReporter:
    """Generates an HTML security report."""

    def report(self, result: ScanResult) -> str:
        summary = result.summary()
        vulns_html = self._render_vulns(result.vulnerabilities)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DjangoSentinel Security Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #0d1117; color: #e6edf3; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
  header {{ text-align: center; padding: 3rem 0 2rem; border-bottom: 1px solid #30363d; }}
  header h1 {{ font-size: 2rem; color: #58a6ff; }}
  header p {{ color: #8b949e; margin-top: 0.5rem; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
              gap: 1rem; margin: 2rem 0; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 1.2rem; text-align: center; }}
  .stat-value {{ font-size: 2rem; font-weight: bold; }}
  .stat-label {{ color: #8b949e; font-size: 0.85rem; margin-top: 0.3rem; }}
  .critical {{ color: #f85149; border-color: #f85149; }}
  .high {{ color: #e3b341; border-color: #e3b341; }}
  .medium {{ color: #d29922; border-color: #d29922; }}
  .low {{ color: #58a6ff; border-color: #58a6ff; }}
  .vuln {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           margin: 1rem 0; overflow: hidden; }}
  .vuln-header {{ display: flex; align-items: center; gap: 0.75rem; padding: 1rem 1.25rem;
                  cursor: pointer; }}
  .badge {{ padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  .badge-CRITICAL {{ background: rgba(248,81,73,0.2); color: #f85149; }}
  .badge-HIGH {{ background: rgba(227,179,65,0.2); color: #e3b341; }}
  .badge-MEDIUM {{ background: rgba(210,153,34,0.2); color: #d29922; }}
  .badge-LOW {{ background: rgba(88,166,255,0.2); color: #58a6ff; }}
  .vuln-title {{ font-weight: 600; flex: 1; }}
  .vuln-body {{ padding: 1.25rem; border-top: 1px solid #30363d; }}
  .location {{ font-family: 'SFMono-Regular', monospace; font-size: 0.85rem;
               color: #8b949e; background: #0d1117; padding: 0.3rem 0.6rem;
               border-radius: 4px; display: inline-block; margin: 0.5rem 0; }}
  .fix-block {{ background: rgba(40,167,69,0.1); border: 1px solid rgba(40,167,69,0.3);
                border-radius: 6px; padding: 1rem; margin-top: 1rem; }}
  .fix-block h4 {{ color: #3fb950; margin-bottom: 0.5rem; }}
  pre {{ background: #0d1117; padding: 0.8rem; border-radius: 4px; overflow-x: auto;
         font-size: 0.8rem; border: 1px solid #30363d; }}
  .meta {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 0.5rem; }}
  .meta span {{ font-size: 0.8rem; color: #8b949e; background: #0d1117;
                padding: 0.2rem 0.5rem; border-radius: 4px; }}
  footer {{ text-align: center; color: #8b949e; padding: 2rem 0; border-top: 1px solid #30363d; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🛡️ DjangoSentinel Security Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; Scan ID: {summary['scan_id']}</p>
    <p>Project: <code>{summary['project']}</code></p>
  </header>

  <div class="summary">
    <div class="stat"><div class="stat-value">{summary['files_scanned']}</div><div class="stat-label">Files Scanned</div></div>
    <div class="stat critical"><div class="stat-value">{summary['by_severity']['critical']}</div><div class="stat-label">Critical</div></div>
    <div class="stat high"><div class="stat-value">{summary['by_severity']['high']}</div><div class="stat-label">High</div></div>
    <div class="stat medium"><div class="stat-value">{summary['by_severity']['medium']}</div><div class="stat-label">Medium</div></div>
    <div class="stat low"><div class="stat-value">{summary['by_severity']['low']}</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-value">{summary['fixable']}</div><div class="stat-label">Auto-Fixable</div></div>
  </div>

  <h2 style="margin-bottom:1rem">Vulnerabilities</h2>
  {vulns_html}

  <footer>DjangoSentinel v1.0.0 — Enterprise Security for Python/Django</footer>
</div>
</body>
</html>"""

    def _render_vulns(self, vulns: List[Vulnerability]) -> str:
        if not vulns:
            return '<p style="color:#3fb950;font-size:1.2rem">✅ No vulnerabilities found!</p>'

        parts = []
        for v in sorted(vulns, key=lambda x: list(Severity).index(x.severity)):
            fix_html = ""
            if v.fix:
                applied = "✅ FIXED" if v.fix.applied else ""
                fix_html = f"""
                <div class="fix-block">
                  <h4>💊 Fix: {html.escape(v.fix.description)} {applied}</h4>
                  <p style="font-size:0.85rem;color:#8b949e">{html.escape(v.fix.explanation)}</p>
                  <pre>{html.escape(v.fix.fixed_code)}</pre>
                  {'<p style="color:#d29922">⚠️ Requires manual review</p>' if v.fix.manual_review_required else ''}
                </div>"""

            snippet = f'<pre>{html.escape(v.location.snippet or "")}</pre>' if v.location.snippet and "[REDACTED]" not in (v.location.snippet or "") else ""

            parts.append(f"""
            <div class="vuln">
              <div class="vuln-header">
                <span class="badge badge-{v.severity.value}">{v.severity.value}</span>
                <span class="vuln-title">{html.escape(v.title)}</span>
              </div>
              <div class="vuln-body">
                <div class="location">📍 {html.escape(str(v.location))}</div>
                <p style="margin:0.75rem 0">{html.escape(v.description)}</p>
                {snippet}
                <div class="meta">
                  <span>ID: {v.vuln_id}</span>
                  <span>{html.escape(v.cwe_id)}</span>
                  <span>{html.escape(v.cve_id or v.owasp_ref)}</span>
                  <span>{html.escape(v.category.value)}</span>
                </div>
                {fix_html}
              </div>
            </div>""")
        return "\n".join(parts)


class SARIFReporter:
    """
    SARIF 2.1.0 reporter for GitHub Code Scanning integration.
    Upload the output to GitHub via Code Scanning API.
    """

    SEVERITY_MAP = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }

    def report(self, result: ScanResult) -> str:
        rules = {}
        results = []

        for v in result.vulnerabilities:
            rule_id = v.vuln_id
            rules[rule_id] = {
                "id": rule_id,
                "name": v.title.replace(" ", ""),
                "shortDescription": {"text": v.title},
                "fullDescription": {"text": v.description},
                "helpUri": v.references[0] if v.references else f"https://cwe.mitre.org/data/definitions/{v.cwe_id.replace('CWE-', '')}.html",
                "properties": {
                    "tags": [v.category.value, v.owasp_ref],
                    "precision": "high",
                    "problem.severity": self.SEVERITY_MAP[v.severity],
                },
            }

            results.append({
                "ruleId": rule_id,
                "level": self.SEVERITY_MAP[v.severity],
                "message": {"text": v.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": v.location.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": v.location.line_number,
                            "snippet": {"text": v.location.snippet or ""},
                        },
                    }
                }],
                "fixes": [{
                    "description": {"text": v.fix.description},
                    "artifactChanges": [],
                }] if v.fix else [],
            })

        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "DjangoSentinel",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/yourusername/django-sentinel",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }],
        }

        return json.dumps(sarif, indent=2)
