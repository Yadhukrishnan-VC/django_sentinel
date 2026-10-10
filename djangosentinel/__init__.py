"""
DjangoSentinel — Enterprise AI Security Scanner for Python/Django
Finds and auto-fixes vulnerabilities before production.

Architecture:
Rule Engine   → fast regex + AST patterns (always runs)
AST Engine    → structural code analysis (always runs)
Taint Engine  → data-flow tracking source→sink (always runs)
AI Engine     → Claude-powered fixes, explanations, PR summaries (--ai)
Diff Engine   → git-diff scoped scanning (--diff)
Cache Engine  → file-hash incremental scanning (automatic)
"""

__version__ = "1.0.0"
__author__ = "DjangoSentinel Contributors"
__all__ = [
    # Core models
    "Vulnerability", "Fix", "CodeLocation", "ScanResult", "Severity", "VulnCategory",
    # Scanners
    "DjangoScanner", "ASTScanner", "BusinessLogicScanner", "DependencyScanner",
    "DiffScanner", "DiffParser", "GitDiffSource",
    # Analysis
    "DataFlowTracker", "deduplicate", "apply_confidence_scores",
    "filter_by_confidence", "score_label", "score_emoji",
    # Fixers
    "AutoFixer", "ContextAwareFixer", "ASTSafeFixer",
    # Reporters
    "TerminalReporter", "JSONReporter", "HTMLReporter", "SARIFReporter", "DiffReporter",
    # AI
    "AIFixEngine", "AIExplainer", "AIPatternScanner", "PRReviewSummarizer",
    # GitHub
    "GitHubPRIntegration",
    # Cache
    "ScanCache", "IncrementalScanner",
    # Hooks
    "HookInstaller",
]
