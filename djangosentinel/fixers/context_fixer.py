"""
Context-Aware Fixer — DjangoSentinel
=====================================
Combines the rule-based AutoFixer with AI-assisted fixing for
complex, multi-line, context-dependent vulnerabilities.

Strategy:
1. Rule-based fix available AND not manual_review_required → apply directly (fast, free)
2. Fix is manual_review_required OR placeholder comment → ask AI for a better fix
3. AI unavailable (no API key) → fall back to showing the hint from the rule engine
4. AI fix generated → store on vuln.fix, apply with backup protection

Context extraction:
For every vulnerability that needs AI, we extract the surrounding N lines
of source code so Claude sees the full function/class context, not just
the single guilty line.
"""

import shutil
from pathlib import Path
from typing import List, Dict, Tuple
from datetime import datetime

from djangosentinel.models import Vulnerability, Fix
from djangosentinel.fixers.auto_fixer import AutoFixer


class ContextAwareFixer:
    """
    Enhanced fixer that:
    - Applies simple rule-based fixes directly
    - Extracts rich code context for AI-powered fixes
    - Uses AI to generate multi-line refactoring for complex issues
    - Provides detailed, actionable output per vulnerability
    """

    CONTEXT_LINES = 20  # lines before+after vulnerability for AI context

    def __init__(
        self,
        project_path: str,
        ai_engine=None,
        dry_run: bool = False,
        backup: bool = True,
    ):
        self.project_path = Path(project_path)
        self.ai_engine = ai_engine  # AIFixEngine instance or None
        self.dry_run = dry_run
        self.backup = backup
        self.backup_dir = (
            self.project_path / ".sentinel_backups" /
            datetime.now().strftime("%Y%m%d_%H%M%S")
        )
        self.results: Dict[str, List[dict]] = {}  # file → list of fix results

    def fix_all(self, vulnerabilities: List[Vulnerability]) -> Tuple[int, int, int]:
        """
        Apply fixes to all vulnerabilities.

        Returns:
            (rule_fixed, ai_fixed, manual_count)
        """
        rule_fixed = 0
        ai_fixed = 0
        manual = []

        # Separate into rule-fixable and AI-needed
        rule_fixable = []
        ai_needed = []

        for v in vulnerabilities:
            if v.fix is None:
                manual.append(v)
            elif v.fix.manual_review_required:
                ai_needed.append(v)
            elif v.fix.fixed_code.startswith("#"):
                # Placeholder hint-only fix → try AI
                ai_needed.append(v)
            else:
                rule_fixable.append(v)

        # Step 1: Apply simple rule-based fixes
        if rule_fixable and not self.dry_run:
            base_fixer = AutoFixer(
                str(self.project_path), dry_run=False, backup=self.backup
            )
            rule_fixed, _ = base_fixer.apply_fixes(rule_fixable)

        # Step 2: Try AI for complex fixes
        if self.ai_engine and self.ai_engine.available:
            for v in ai_needed:
                context = self._extract_context(v)
                ai_fix = self.ai_engine.generate_fix(v, file_context=context)
                if ai_fix:
                    v.fix = ai_fix
                    if not self.dry_run:
                        if self._apply_fix(v, ai_fix):
                            ai_fix.applied = True
                            ai_fixed += 1
                            self._record(v, "ai_fixed")
                        else:
                            self._record(v, "ai_failed")
                    else:
                        self._record(v, "ai_dry_run")
                else:
                    self._record(v, "manual")
        else:
            for v in ai_needed:
                self._record(v, "manual")

        return rule_fixed, ai_fixed, len(manual) + len(ai_needed) - ai_fixed

    def _extract_context(self, vuln: Vulnerability) -> str:
        """
        Extract surrounding lines of code for the vulnerability location.
        Gives AI the full function/class context instead of just one line.
        """
        file_path = self.project_path / vuln.location.file_path
        if not file_path.exists():
            return ""

        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            lineno = vuln.location.line_number - 1  # 0-indexed
            start = max(0, lineno - self.CONTEXT_LINES)
            end = min(len(lines), lineno + self.CONTEXT_LINES)
            context_lines = lines[start:end]
            # Add line numbers for AI reference
            numbered = [
                f"{start + i + 1:4d} | {line}"
                for i, line in enumerate(context_lines)
            ]
            return "\n".join(numbered)
        except Exception:
            return ""

    def _apply_fix(self, vuln: Vulnerability, fix: Fix) -> bool:
        """Apply a fix to the actual file using AST-safe indentation-preserving method."""
        from djangosentinel.fixers.ast_safe_fixer import ASTSafeFixer
        ast_fixer = ASTSafeFixer(
            str(self.project_path),
            dry_run=self.dry_run,
            backup=self.backup,
        )
        return ast_fixer.apply_fix(vuln)

    def _backup_file(self, file_path: Path):
        """Create a backup of the file before modification."""
        try:
            rel = file_path.relative_to(self.project_path)
            dst = self.backup_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if not dst.exists():  # only backup once per session
                shutil.copy2(file_path, dst)
        except Exception:
            pass

    def _record(self, vuln: Vulnerability, status: str):
        """Record the fix outcome for reporting."""
        fp = vuln.location.file_path
        if fp not in self.results:
            self.results[fp] = []
        self.results[fp].append({
            "title": vuln.title,
            "severity": vuln.severity.value,
            "line": vuln.location.line_number,
            "status": status,
            "fix_hint": vuln.fix.explanation if vuln.fix else "",
        })

    def generate_report(self, rule_fixed: int, ai_fixed: int, manual: int) -> str:
        """Generate a human-readable context-aware fix report."""
        lines = [
            "",
            "╔══════════════════════════════════════════════════╗",
            "║          🔧 CONTEXT-AWARE FIX REPORT             ║",
            "╚══════════════════════════════════════════════════╝",
            "",
        ]

        if self.dry_run:
            lines.append("  MODE: DRY RUN — no files were modified\n")

        ai_status = (
            "✅ Available" if (self.ai_engine and self.ai_engine.available)
            else "❌ No API key (set ANTHROPIC_API_KEY)"
        )
        lines.append(f"  AI Engine: {ai_status}")
        lines.append(f"  Backup:    {'✅ ' + str(self.backup_dir) if self.backup else '⚠️  Disabled'}")
        lines.append("")

        # Summary table
        total_fixed = rule_fixed + ai_fixed
        lines.append("  RESULTS")
        lines.append("  " + "─" * 40)
        lines.append(f"  ✅ Rule-based fixes applied:  {rule_fixed}")
        lines.append(f"  🤖 AI-powered fixes applied:  {ai_fixed}")
        lines.append(f"  ⚠️  Require manual review:    {manual}")
        lines.append(f"  {'─' * 30}")
        lines.append(f"  Total fixed: {total_fixed}")
        lines.append("")

        # Per-file breakdown
        if self.results:
            lines.append("  PER-FILE BREAKDOWN")
            lines.append("  " + "─" * 40)
            for filepath, fixes in self.results.items():
                lines.append(f"\n  📄 {filepath}")
                for fix_info in fixes:
                    status_icon = {
                        "ai_fixed": "🤖✅",
                        "ai_dry_run": "🤖👁️",
                        "ai_failed": "🤖❌",
                        "manual": "⚠️ ",
                    }.get(fix_info["status"], "✅")
                    lines.append(
                        f"     {status_icon} [{fix_info['severity']}] "
                        f"Line {fix_info['line']}: {fix_info['title']}"
                    )
                    if fix_info["status"] == "manual" and fix_info["fix_hint"]:
                        lines.append(f"        💡 {fix_info['fix_hint']}")

        lines.append("")
        if manual > 0:
            lines.append("  ℹ️  For manual-review issues, run:")
            lines.append("     sentinel scan . --format html -o report.html")
            lines.append("     Open report.html for detailed fix guidance per issue.")
        lines.append("")
        return "\n".join(lines)
