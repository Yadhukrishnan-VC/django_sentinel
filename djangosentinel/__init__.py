"""
DjangoSentinel — Enterprise AI Security Scanner for Python/Django
Finds and auto-fixes vulnerabilities before production.

Architecture:
Rule Engine   → fast regex + AST patterns (always runs)
AST Engine    → structural code analysis (always runs)
Taint Engine  → data-flow tracking source→sink (always runs)
AI Engine     → Claude / OpenAI / Gemini fixes, explanations, PR summaries (--ai)
Diff Engine   → git-diff scoped scanning (--diff)
Cache Engine  → file-hash scan cache (ScanCache / IncrementalScanner, --clear-cache)

Public names are imported lazily (PEP 562), so ``import djangosentinel`` stays
fast and ``from djangosentinel import DjangoScanner`` (or ``import *``) works.
"""

import importlib

__version__ = "1.0.0"
__author__ = "DjangoSentinel Contributors"

# public name -> module that defines it
_EXPORTS = {
    # Core models
    "Vulnerability": "djangosentinel.models", "Fix": "djangosentinel.models",
    "CodeLocation": "djangosentinel.models", "ScanResult": "djangosentinel.models",
    "Severity": "djangosentinel.models", "VulnCategory": "djangosentinel.models",
    # Scanners
    "DjangoScanner": "djangosentinel.scanners", "ASTScanner": "djangosentinel.scanners",
    "BusinessLogicScanner": "djangosentinel.scanners", "DependencyScanner": "djangosentinel.scanners",
    "DiffScanner": "djangosentinel.scanners", "DiffParser": "djangosentinel.scanners",
    "GitDiffSource": "djangosentinel.scanners",
    # Analysis
    "DataFlowTracker": "djangosentinel.analysis", "deduplicate": "djangosentinel.analysis",
    "apply_confidence_scores": "djangosentinel.analysis",
    "filter_by_confidence": "djangosentinel.analysis",
    "score_label": "djangosentinel.analysis", "score_emoji": "djangosentinel.analysis",
    # Fixers
    "AutoFixer": "djangosentinel.fixers", "ContextAwareFixer": "djangosentinel.fixers",
    "ASTSafeFixer": "djangosentinel.fixers",
    # Reporters
    "TerminalReporter": "djangosentinel.reporters", "JSONReporter": "djangosentinel.reporters",
    "HTMLReporter": "djangosentinel.reporters", "SARIFReporter": "djangosentinel.reporters",
    "DiffReporter": "djangosentinel.reporters",
    # AI
    "AIFixEngine": "djangosentinel.ai_engine", "AIExplainer": "djangosentinel.ai_engine",
    "AIPatternScanner": "djangosentinel.ai_engine", "PRReviewSummarizer": "djangosentinel.ai_engine",
    # GitHub
    "GitHubPRIntegration": "djangosentinel.github_integration",
    # Cache
    "ScanCache": "djangosentinel.cache", "IncrementalScanner": "djangosentinel.cache",
    # Hooks
    "HookInstaller": "djangosentinel.hooks",
}

__all__ = list(_EXPORTS)


def __getattr__(name):
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module 'djangosentinel' has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value  # cache for next time
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
