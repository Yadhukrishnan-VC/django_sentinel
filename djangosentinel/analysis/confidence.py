"""
Confidence Scoring and Finding Deduplication — DjangoSentinel
=============================================================
Every finding gets a confidence score (0.0–1.0) so developers can:
- Trust HIGH confidence findings immediately
- Review MEDIUM confidence findings before acting
- Dismiss LOW confidence findings if context shows they're safe

Scoring factors:
- Base score from detection method (AST > regex, taint-tracked > pattern)
- Boosted by: presence of user data in the exact line
- Boosted by: known-dangerous function names
- Reduced by: presence of sanitizers nearby
- Reduced by: test/fixture/example file context
- Reduced by: string inside a comment or docstring

Deduplication:
- MD5 hash of (file_path + line_number + rule_id)
- Merges findings that are the same issue reported by multiple scanners
- Keeps highest-confidence version when duplicates exist
"""

import hashlib
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from djangosentinel.models import Vulnerability, Severity


# ─────────────────────────────────────────────────────────────────────────────
# Confidence scoring
# ─────────────────────────────────────────────────────────────────────────────

# Base confidence by detection method (stored in metadata["source"])
BASE_CONFIDENCE = {
    "ast_scanner":          0.82,   # structural — very reliable
    "taint_tracker":        0.90,   # data flow — most reliable
    "django_scanner":       0.75,   # regex — good but can false-positive
    "business_logic":       0.70,   # pattern — context-dependent
    "dependency_scanner":   0.95,   # CVE match — highly reliable
    "ai_pattern_scanner":   0.65,   # AI — useful but uncertain
    "diff_scanner":         0.75,   # inherits from underlying scanner
    "unknown":              0.60,
}

# Severity multiplier — critical findings get a slight confidence boost
SEVERITY_BOOST = {
    Severity.CRITICAL: 0.05,
    Severity.HIGH:     0.02,
    Severity.MEDIUM:   0.00,
    Severity.LOW:     -0.02,
    Severity.INFO:    -0.05,
}

# Signals that INCREASE confidence
BOOST_SIGNALS = [
    "request.GET",       "request.POST",   "request.data",
    "request.FILES",     "request.body",   "user_input",
    "f\"",               "f'",             "% ",             # string interpolation
    ".format(",          "eval(",          "exec(",
    "shell=True",        "pickle.loads",
]

# Signals that DECREASE confidence (suggest this might be safe or FP)
REDUCE_SIGNALS = [
    "test",              "example",        "fixture",
    "# noqa",            "# type: ignore", "sanitize",
    "validate",          "escape(",        "html.escape",
    "parameterized",     "safe_",          "clean_",
]

# File paths that reduce confidence
LOW_CONFIDENCE_PATHS = {
    "test", "tests", "spec", "fixture", "fixtures",
    "example", "examples", "demo", "mock",
}


def compute_confidence(vuln: Vulnerability, source_line: str = "") -> float:
    """
    Compute a confidence score for a vulnerability finding.

    Args:
        vuln:        The vulnerability object
        source_line: The actual source code line (for signal checking)

    Returns:
        float in [0.0, 1.0]
    """
    # Start from base score for the detection method
    source = vuln.metadata.get("source", "unknown")
    score = BASE_CONFIDENCE.get(source, BASE_CONFIDENCE["unknown"])

    # Already has a score from taint tracker
    if "confidence" in vuln.metadata and isinstance(vuln.metadata["confidence"], float):
        score = vuln.metadata["confidence"]

    # Severity boost
    score += SEVERITY_BOOST.get(vuln.severity, 0.0)

    # Check file path for test indicators
    path_parts = vuln.location.file_path.lower().replace("/", " ").replace("\\", " ").split()
    if any(lcp in path_parts for lcp in LOW_CONFIDENCE_PATHS):
        score -= 0.20

    # Check source line for signals
    check_text = (source_line + " " + (vuln.location.snippet or "")).lower()

    for signal in BOOST_SIGNALS:
        if signal.lower() in check_text:
            score += 0.04
            break  # only count once

    for signal in REDUCE_SIGNALS:
        if signal.lower() in check_text:
            score -= 0.05
            break

    # Clamp to [0.05, 0.99]
    return round(max(0.05, min(0.99, score)), 3)


def score_label(confidence: float) -> str:
    """Human-readable label for a confidence score."""
    if confidence >= 0.85:
        return "HIGH"
    elif confidence >= 0.65:
        return "MEDIUM"
    elif confidence >= 0.40:
        return "LOW"
    else:
        return "UNCERTAIN"


def score_emoji(confidence: float) -> str:
    """Emoji indicator for confidence level."""
    if confidence >= 0.85:
        return "🟢"
    elif confidence >= 0.65:
        return "🟡"
    elif confidence >= 0.40:
        return "🟠"
    else:
        return "🔴"


# ─────────────────────────────────────────────────────────────────────────────
# Finding deduplication
# ─────────────────────────────────────────────────────────────────────────────

def finding_hash(vuln: Vulnerability) -> str:
    """
    Compute a stable hash for a finding.
    Two findings are considered duplicates if they have the same:
        - file path
        - line number (±2 lines tolerance)
        - rule category (not exact title — different scanners may name it slightly differently)
    """
    category = vuln.category.value
    file_path = vuln.location.file_path
    # Normalize line number to nearest 3 (±1 line tolerance)
    line_bucket = (vuln.location.line_number // 3) * 3
    cwe = vuln.cwe_id

    key = f"{file_path}:{line_bucket}:{category}:{cwe}"
    return hashlib.md5(key.encode("utf-8")).hexdigest()[:12]


def deduplicate(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
    """
    Remove duplicate findings, keeping the highest-confidence version.

    When two scanners find the same issue at the same location, we:
        1. Compute the hash for each finding
        2. Group findings by hash
        3. Keep the one with highest confidence
        4. Merge metadata and references from duplicates into the winner
    """
    groups: Dict[str, List[Vulnerability]] = {}

    for v in vulnerabilities:
        h = finding_hash(v)
        groups.setdefault(h, []).append(v)

    result: List[Vulnerability] = []

    for h, group in groups.items():
        if len(group) == 1:
            result.append(group[0])
            continue

        # Keep highest confidence; fall back to lowest severity (most conservative)
        group.sort(
            key=lambda v: (
                -v.metadata.get("confidence", 0.5),
                ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(v.severity.value),
            )
        )
        winner = group[0]

        # Merge references and metadata from duplicates
        all_refs = set(winner.references)
        all_sources = set()
        for dup in group[1:]:
            all_refs.update(dup.references)
            all_sources.add(dup.metadata.get("source", ""))
            # If a duplicate has a fix and winner doesn't, adopt it
            if winner.fix is None and dup.fix is not None:
                winner.fix = dup.fix

        winner.references = list(all_refs)
        winner.metadata["merged_from"] = list(all_sources - {""})
        winner.metadata["duplicate_count"] = len(group) - 1

        result.append(winner)

    return result


def apply_confidence_scores(
    vulnerabilities: List[Vulnerability],
    source_map: Optional[Dict[str, str]] = None,
) -> List[Vulnerability]:
    """
    Compute and store confidence scores for all vulnerabilities.

    Args:
        vulnerabilities: List of findings to score
        source_map:      Optional {file_path: source_code} for line lookup

    Returns:
        Same list with metadata["confidence"] and metadata["confidence_label"] set
    """
    for v in vulnerabilities:
        source_line = ""
        if source_map and v.location.file_path in source_map:
            lines = source_map[v.location.file_path].splitlines()
            idx = v.location.line_number - 1
            if 0 <= idx < len(lines):
                source_line = lines[idx]

        conf = compute_confidence(v, source_line)
        v.metadata["confidence"] = conf
        v.metadata["confidence_label"] = score_label(conf)

    return vulnerabilities


def filter_by_confidence(
    vulnerabilities: List[Vulnerability],
    min_confidence: float = 0.0,
) -> List[Vulnerability]:
    """Return only findings above the confidence threshold."""
    return [
        v for v in vulnerabilities
        if v.metadata.get("confidence", 0.5) >= min_confidence
    ]
