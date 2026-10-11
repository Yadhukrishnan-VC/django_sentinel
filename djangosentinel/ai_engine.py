"""
AI-Powered Analysis Engine - DjangoSentinel
============================================
Uses Claude (claude-sonnet-4-20250514) for:
1. Complex multi-line fixes that pattern matching can't generate
2. Deep "why is this risky" explanations with project context
3. Edge case detection - unknown patterns LLM can reason about
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
from djangosentinel.ai_model_providers import (
    ai_generate,
    get_ai_provider,
    is_ai_available,
    set_ai_provider,
)


# ---------------------------------------------------------------------------
# Backward-compatible wrapper: delegates to the current default provider.
# By default the provider is Anthropic, so existing code continues to work
# without any changes.
# ---------------------------------------------------------------------------

def _call_claude(
    system: str,
    user: str,
    max_tokens: int = 1500,
    api_key: Optional[str] = None,
    timeout: int = 30,
) -> Optional[str]:
    """Call the default AI provider and return the response text."""
    return ai_generate(system, user, max_tokens, timeout)


# ─────────────────────────────────────────────────────────────────────────────
# AI-Enhanced Fix Generator
# ─────────────────────────────────────────────────────────────────────────────

class AIFixEngine:
    """
    Generates AI-powered fixes for vulnerabilities that rule-based
    fixers cannot handle - multi-line changes, refactoring, context-dependent.
    """

    SYSTEM_PROMPT = """You are DjangoSentinel's AI security fix engine.

Your job is to generate precise, minimal, production-safe code fixes for
Python/Django security vulnerabilities. You must:

1. Output ONLY valid Python code - no markdown fences, no prose, no comments
    unless comments are part of the fix itself
2. Keep changes minimal - fix the vulnerability, change nothing else
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
        response = ai_generate(
            system=self.SYSTEM_PROMPT,
            user=prompt,
            max_tokens=900,
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
- Be direct and specific - reference the actual code, not generic descriptions
- Explain the real-world attack scenario in 2-3 sentences
- Avoid jargon - if you use a term, explain it immediately
- End with one concrete, actionable fix hint
- Maximum 150 words total
- Never use bullet points - write in flowing prose"""

    def __init__(self, api_key: Optional[str] = None):
        if api_key:
            from djangosentinel.ai_model_providers import AnthropicProvider
            self._provider = AnthropicProvider()
            self._provider.api_key = api_key
        else:
            self._provider = get_ai_provider()
        self.available = self._provider.available
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

        response = ai_generate(
            system=self.SYSTEM_PROMPT,
            user=prompt,
            max_tokens=250,
        )

        if response:
            self._cache[cache_key] = response.strip()

        return response.strip() if response else None


# ─────────────────────────────────────────────────────────────────────────────
# AI-Powered Unknown Pattern Scanner
# ─────────────────────────────────────────────────────────────────────────────

    def __init__(self, api_key: Optional[str] = None):
        from djangosentinel.ai_model_providers import AnthropicProvider
        if api_key:
            self._provider = AnthropicProvider()
            self._provider.api_key = api_key
        else:
            from djangosentinel.ai_model_providers import get_ai_provider
            self._provider = get_ai_provider()
        self.available = self._provider.available

