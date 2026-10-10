"""
AI-Powered Analysis Engine — DjangoSentinel
============================================
Uses Claude (claude-sonnet-4-20250514) for:
1. Complex multi-line fixes that pattern matching can't generate
2. Deep "why is this risky" explanations with project context
3. Edge case detection — unknown patterns LLM can reason about
4. PR review summaries for GitHub integration

Rule engine handles:
- Simple pattern detection (fast, zero cost)
- Basic single-line fixes (deterministic)

LLM handles:
- Multi-line refactoring suggestions
- Context-aware explanations
- Unknown/novel vulnerability patterns
- PR-ready markdown summaries
"""

import json
import os
import re
import time
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from djangosentinel.models import (
    Vulnerability, VulnCategory, Severity, CodeLocation, Fix, ScanResult
)


# ─────────────────────────────────────────────────────────────────────────────
# Anthropic API client (no SDK dependency — pure HTTP)
# ─────────────────────────────────────────────────────────────────────────────

ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"


def _call_claude(
    system: str,
    user: str,
    max_tokens: int = 1500,
    api_key: Optional[str] = None,
    timeout: int = 30,
) -> Optional[str]:
    """
    Call Claude API and return the text response.
    Returns None if API key is missing or request fails.
    """
    try:
        import urllib.request
        import urllib.error

        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            return None

        payload = json.dumps({
            "model": ANTHROPIC_MODEL,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode("utf-8")

        req = urllib.request.Request(
            ANTHROPIC_API_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["content"][0]["text"]

    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# AI-Enhanced Fix Generator
# ─────────────────────────────────────────────────────────────────────────────

class AIFixEngine:
    """
    Generates AI-powered fixes for vulnerabilities that rule-based
    fixers cannot handle — multi-line changes, refactoring, context-dependent.
    """

    SYSTEM_PROMPT = """You are DjangoSentinel's AI security fix engine.

Your job is to generate precise, minimal, production-safe code fixes for
Python/Django security vulnerabilities. You must:

1. Output ONLY valid Python code — no markdown fences, no prose, no comments
    unless comments are part of the fix itself
2. Keep changes minimal — fix the vulnerability, change nothing else
3. Preserve the original code's indentation and style exactly
4. When you cannot generate a safe fix, output exactly: MANUAL_REVIEW_REQUIRED

You understand Django ORM, Django security best practices, OWASP Top 10,
race conditions, authentication patterns, and common Django anti-patterns."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.available = bool(self.api_key)
        self._cache: Dict[str, str] = {}

    def generate_fix(
        self,
        vuln: Vulnerability,
        file_context: str = "",
        surrounding_lines: int = 10,
    ) -> Optional[Fix]:
        """
        Generate an AI-powered fix for a vulnerability that needs multi-line
        changes or complex refactoring.

        Only called for vulns where manual_review_required=True or
        where the existing fix.fixed_code is a placeholder comment.
        """
        if not self.available:
            return None

        # Build cache key from vuln signature
        cache_key = f"{vuln.title}:{vuln.location}:{hash(file_context[:200])}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            return self._build_fix(cached, vuln)

        prompt = self._build_prompt(vuln, file_context)
        response = _call_claude(
            system=self.SYSTEM_PROMPT,
            user=prompt,
            max_tokens=900,
            api_key=self.api_key,
        )

        if not response:
            return None

        response = response.strip()
        self._cache[cache_key] = response
        return self._build_fix(response, vuln)

    def _build_prompt(self, vuln: Vulnerability, file_context: str) -> str:
        snippet = vuln.location.snippet or ""
        # Detect view type from context for smart fix selection
        is_cbv = any(kw in file_context for kw in ["self.request", "LoginRequiredMixin", "get_queryset"])
        view_type = "class-based view" if is_cbv else "function-based view"

        return f"""You are a Django security expert. Fix this specific vulnerability.

VULNERABILITY TYPE: {vuln.category.value}
SEVERITY: {vuln.severity.value}
CWE: {vuln.cwe_id}
OWASP: {vuln.owasp_ref}
TITLE: {vuln.title}

VULNERABLE CODE (line {vuln.location.line_number} in {view_type}):
```python
{snippet}
```

SURROUNDING CONTEXT (lines {max(1, vuln.location.line_number - 10)} to {vuln.location.line_number + 10}):
```python
{file_context}
```

TASK: Fix ONLY the vulnerability above. Do not refactor unrelated code.
Preserve the exact indentation. Return valid JSON only."""

    def _build_fix(self, response: str, vuln: Vulnerability) -> Optional[Fix]:
        """Parse structured JSON response from Claude."""
        import json as _json
        try:
            clean = re.sub(r"```json|```", "", response).strip()
            data = _json.loads(clean)
        except (_json.JSONDecodeError, ValueError):
            # Fallback: treat entire response as code
            data = {"fixed_code": response, "explanation": "", "confidence": 0.65}

        fixed_code = data.get("fixed_code")
        if not fixed_code:
            return None

        explanation = data.get("explanation", f"AI-generated fix for {vuln.cwe_id}.")
        confidence = float(data.get("confidence", 0.70))
        test_hint = data.get("test_hint", "")

        return Fix(
            description=f"AI fix [{confidence:.0%} confidence]: {vuln.title}",
            original_code=vuln.location.snippet or "",
            fixed_code=fixed_code,
            applied=False,
            manual_review_required=confidence < 0.70,
            explanation=explanation + (f" | Test: {test_hint}" if test_hint else ""),
        )


# ─────────────────────────────────────────────────────────────────────────────
# AI Explanation Engine
# ─────────────────────────────────────────────────────────────────────────────

class AIExplainer:
    """
    Generates developer-friendly explanations of why a vulnerability is risky,
    tailored to the specific code context found in the project.
    """

    SYSTEM_PROMPT = """You are a senior Django security engineer explaining vulnerabilities to developers.

Rules:
- Be direct and specific — reference the actual code, not generic descriptions
- Explain the real-world attack scenario in 2-3 sentences
- Avoid jargon — if you use a term, explain it immediately
- End with one concrete, actionable fix hint
- Maximum 150 words total
- Never use bullet points — write in flowing prose"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.available = bool(self.api_key)
        self._cache: Dict[str, str] = {}

    def explain(self, vuln: Vulnerability, code_context: str = "") -> Optional[str]:
        """
        Return a rich, context-aware explanation of why this specific
        instance of the vulnerability is dangerous.
        """
        if not self.available:
            return None

        cache_key = f"explain:{vuln.vuln_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        prompt = f"""Explain this specific Django vulnerability to a developer:

Vulnerability: {vuln.title}
Location: {vuln.location.file_path} line {vuln.location.line_number}
Code: {vuln.location.snippet or 'N/A'}
Context: {code_context[:300] if code_context else 'N/A'}
CWE: {vuln.cwe_id}

Write a developer-friendly explanation of WHY this specific code is dangerous
and what an attacker could do with it."""

        response = _call_claude(
            system=self.SYSTEM_PROMPT,
            user=prompt,
            max_tokens=250,
            api_key=self.api_key,
        )

        if response:
            self._cache[cache_key] = response.strip()

        return response.strip() if response else None


# ─────────────────────────────────────────────────────────────────────────────
# AI-Powered Unknown Pattern Scanner
# ─────────────────────────────────────────────────────────────────────────────

class AIPatternScanner:
    """
    Submits code snippets to Claude for reasoning about security issues
    that rule-based patterns cannot catch — novel patterns, complex logic,
    project-specific anti-patterns.

    Only runs on files that rule scanners flagged OR on files the user
    explicitly requests deep analysis for (--ai-deep flag).
    """

    SYSTEM_PROMPT = """You are a Django security code reviewer.

Analyze the provided Python/Django code for security vulnerabilities that
static analysis tools typically miss. Focus on:
- Business logic flaws (race conditions, missing authorization)
- Novel injection patterns
- Insecure data flows
- Authentication/authorization gaps
- Django-specific misconfigurations

Respond ONLY with valid JSON matching this schema exactly:
{
"vulnerabilities": [
    {
        "title": "Short vulnerability title",
        "severity": "CRITICAL|HIGH|MEDIUM|LOW",
        "line_hint": 12,
        "description": "What is wrong and why it is dangerous (2-3 sentences)",
        "fix_hint": "Concrete fix suggestion (1-2 sentences)",
        "cwe": "CWE-XXX"
    }
]
}

If no vulnerabilities are found, respond with: {"vulnerabilities": []}
Never add prose outside the JSON."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.available = bool(self.api_key)

    def scan_file(self, file_path: str, source: str) -> List[Vulnerability]:
        """
        Ask Claude to reason about security issues in the given source code.
        Returns a list of Vulnerability objects.
        """
        if not self.available or not source.strip():
            return []

        # Skip files that are clearly not security-relevant
        if self._is_boring_file(file_path, source):
            return []

        prompt = f"""Review this Django file for security vulnerabilities:

File: {file_path}
```python
{source[:4000]}
```

Find vulnerabilities that static analysis tools miss — focus on logic flaws,
missing auth checks, race conditions, and insecure data flows."""

        response = _call_claude(
            system=self.SYSTEM_PROMPT,
            user=prompt,
            max_tokens=1200,
            api_key=self.api_key,
            timeout=45,
        )

        if not response:
            return []

        return self._parse_response(response, file_path)

    def _is_boring_file(self, file_path: str, source: str) -> bool:
        """Skip files that are very unlikely to have security issues."""
        boring_names = {"__init__", "admin", "apps", "migrations", "conftest", "setup"}
        stem = Path(file_path).stem.lower()
        if stem in boring_names:
            return True
        # Skip very short files
        if len(source.splitlines()) < 5:
            return True
        # Skip files without Django imports
        if "django" not in source and "request" not in source:
            return True
        return False

    def _parse_response(self, response: str, file_path: str) -> List[Vulnerability]:
        import uuid as _uuid

        vulns = []
        try:
            # Strip any markdown fences if Claude slipped them in
            clean = re.sub(r"```json|```", "", response).strip()
            data = json.loads(clean)
            items = data.get("vulnerabilities", [])

            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }

            for item in items:
                sev = severity_map.get(item.get("severity", "MEDIUM"), Severity.MEDIUM)
                cwe = item.get("cwe", "")
                fix_hint = item.get("fix_hint", "")

                vulns.append(Vulnerability(
                    vuln_id=str(_uuid.uuid4())[:8],
                    title=f"[AI] {item.get('title', 'Unknown Vulnerability')}",
                    category=VulnCategory.BUSINESS_LOGIC,
                    severity=sev,
                    location=CodeLocation(
                        file_path=file_path,
                        line_number=item.get("line_hint", 1),
                        snippet="(AI-detected — see description)",
                    ),
                    description=item.get("description", ""),
                    owasp_ref="A04:2021 – Insecure Design",
                    cwe_id=cwe,
                    fix=Fix(
                        description="AI-suggested fix",
                        original_code="",
                        fixed_code=fix_hint,
                        manual_review_required=True,
                        explanation="AI-detected issue. Always verify before acting.",
                    ),
                    metadata={"source": "ai_pattern_scanner"},
                ))

        except (json.JSONDecodeError, KeyError, TypeError):
            pass

        return vulns


# ─────────────────────────────────────────────────────────────────────────────
# GitHub PR Review Summarizer
# ─────────────────────────────────────────────────────────────────────────────

class PRReviewSummarizer:
    """
    Generates a GitHub Pull Request security review comment in Markdown.
    Designed to be posted via the GitHub API as a PR review comment.
    """

    SYSTEM_PROMPT = """You are DjangoSentinel generating a GitHub Pull Request security review.

Format your response as clean GitHub Markdown suitable for a PR comment.
Be concise, developer-friendly, and actionable.
Use emojis sparingly — only 🔴🟠🟡🔵 for severity, ✅ for fixed, ⚠️ for warnings.
Never be alarmist — be collegial, like a senior developer reviewing a colleague's PR."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.available = bool(self.api_key)

    def generate_pr_comment(
        self,
        result: ScanResult,
        pr_title: str = "",
        changed_files: Optional[List[str]] = None,
    ) -> str:
        """
        Generate a complete PR security review comment.
        Falls back to a template-based comment if AI is unavailable.
        """
        if not self.available or not result.vulnerabilities:
            return self._template_comment(result, changed_files)

        summary = result.summary()
        vuln_details = "\n".join([
            f"- [{v.severity.value}] {v.title} @ {v.location.file_path}:{v.location.line_number}"
            for v in result.vulnerabilities[:15]  # cap at 15 for prompt size
        ])

        prompt = f"""Generate a GitHub PR security review comment for this scan:

PR Title: {pr_title or 'Untitled PR'}
Files Changed: {', '.join(changed_files or []) or 'N/A'}
Total Vulnerabilities: {summary['total_vulnerabilities']}
Critical: {summary['by_severity']['critical']}
High: {summary['by_severity']['high']}
Medium: {summary['by_severity']['medium']}
Low: {summary['by_severity']['low']}
Auto-Fixed: {summary['fixed']}

Findings:
{vuln_details}

Write a PR review comment. Include:
1. A one-sentence summary (pass/needs-work/blocked)
2. Critical and High findings with file:line references
3. What was auto-fixed (if anything)
4. One actionable next step"""

        response = _call_claude(
            system=self.SYSTEM_PROMPT,
            user=prompt,
            max_tokens=800,
            api_key=self.api_key,
        )

        if response:
            return self._wrap_comment(response.strip(), result)

        return self._template_comment(result, changed_files)

    def _wrap_comment(self, content: str, result: ScanResult) -> str:
        summary = result.summary()
        header = "## 🛡️ DjangoSentinel Security Review\n\n"
        footer = (
            f"\n\n---\n"
            f"*DjangoSentinel v1.0.0 — "
            f"Scanned {summary['files_scanned']} files in "
            f"{summary['duration_seconds']:.1f}s*"
        )
        return header + content + footer

    def _template_comment(
        self, result: ScanResult, changed_files: Optional[List[str]]
    ) -> str:
        """Rule-based fallback PR comment (no AI required)."""
        s = result.summary()
        bsev = s["by_severity"]
        total = s["total_vulnerabilities"]

        if total == 0:
            status = "✅ **No vulnerabilities found.** This PR is safe to merge."
        elif bsev["critical"] > 0:
            status = f"🔴 **BLOCKED** — {bsev['critical']} critical issue(s) must be fixed before merge."
        elif bsev["high"] > 0:
            status = f"🟠 **Needs Work** — {bsev['high']} high-severity issue(s) found."
        else:
            status = f"🟡 **Review Suggested** — {total} low/medium issue(s) found."

        lines = [
            "## 🛡️ DjangoSentinel Security Review\n",
            status + "\n",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {bsev['critical']} |",
            f"| 🟠 High | {bsev['high']} |",
            f"| 🟡 Medium | {bsev['medium']} |",
            f"| 🔵 Low | {bsev['low']} |",
            f"| ✅ Auto-Fixed | {s['fixed']} |\n",
        ]

        if result.vulnerabilities:
            lines.append("### Findings\n")
            for v in sorted(result.vulnerabilities,
                            key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x.severity.value)):
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(v.severity.value, "⚪")
                fixed = " ✅" if v.fix and v.fix.applied else ""
                lines.append(f"- {icon} **{v.title}**{fixed} — `{v.location.file_path}:{v.location.line_number}`")
                lines.append(f"  > {v.description[:120]}")

        lines.append(f"\n---\n*DjangoSentinel v1.0.0 — {s['files_scanned']} files · {s['duration_seconds']:.1f}s*")
        return "\n".join(lines)

    def post_to_github(
        self,
        comment: str,
        repo: str,
        pr_number: int,
        token: str,
    ) -> bool:
        """
        Post the review comment to a GitHub PR via the REST API.

        Args:
            comment: Markdown comment text
            repo:    'owner/repo' format
            pr_number: Pull request number
            token:   GitHub personal access token or GITHUB_TOKEN

        Returns:
            True if posted successfully, False otherwise
        """
        try:
            import urllib.request
            import urllib.error

            url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
            payload = json.dumps({"body": comment}).encode("utf-8")

            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "Content-Type": "application/json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status in (200, 201)

        except Exception:
            return False

    def post_inline_annotations(
        self,
        result: ScanResult,
        repo: str,
        pr_number: int,
        commit_sha: str,
        token: str,
    ) -> int:
        """
        Post inline code annotations on specific lines of the PR diff.
        Returns number of annotations successfully posted.
        """
        try:
            import urllib.request

            url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
            comments = []

            for v in result.vulnerabilities:
                if v.fix and v.fix.applied:
                    continue
                body = f"**🛡️ {v.severity.value}: {v.title}**\n\n{v.description}"
                if v.fix and v.fix.explanation:
                    body += f"\n\n**Fix:** {v.fix.explanation}"
                if v.cwe_id:
                    body += f"\n\n*{v.cwe_id} · {v.owasp_ref}*"

                comments.append({
                    "path": v.location.file_path,
                    "line": v.location.line_number,
                    "side": "RIGHT",
                    "body": body,
                })

            if not comments:
                return 0

            severity_counts = result.summary()["by_severity"]
            event = "REQUEST_CHANGES" if severity_counts["critical"] > 0 else "COMMENT"

            payload = json.dumps({
                "commit_id": commit_sha,
                "body": f"DjangoSentinel found {len(result.vulnerabilities)} security issue(s).",
                "event": event,
                "comments": comments[:50],  # GitHub limits to 50 inline comments per review
            }).encode("utf-8")

            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "Content-Type": "application/json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status in (200, 201):
                    return len(comments)
                return 0

        except Exception:
            return 0
