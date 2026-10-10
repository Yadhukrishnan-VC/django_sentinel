"""
Auto-Fixer Engine.
Applies safe, automated fixes to vulnerabilities where the fix is
deterministic and low-risk. High-risk fixes are flagged for manual review.
"""

import re
import shutil
from pathlib import Path
from typing import List, Dict, Tuple
from datetime import datetime

from djangosentinel.models import Vulnerability, Fix, Severity


class AutoFixer:
    """
    Applies automated fixes to detected vulnerabilities.
    Creates backups before modifying any file.
    """

    # Max severity we auto-fix without confirmation
    AUTO_FIX_MAX_SEVERITY = Severity.HIGH

    def __init__(self, project_path: str, dry_run: bool = False, backup: bool = True):
        self.project_path = Path(project_path)
        self.dry_run = dry_run
        self.backup = backup
        self.backup_dir = self.project_path / ".sentinel_backups" / datetime.now().strftime("%Y%m%d_%H%M%S")
        self.fixed_files: Dict[str, List[str]] = {}  # file -> [descriptions]
        self.skipped: List[Vulnerability] = []

    def apply_fixes(self, vulnerabilities: List[Vulnerability]) -> Tuple[int, int]:
        """
        Apply all applicable fixes.
        Returns (fixed_count, skipped_count).
        """
        fixable = [
            v for v in vulnerabilities
            if v.fix is not None
            and not v.fix.applied
            and not v.fix.manual_review_required
        ]

        if not fixable:
            return 0, len([v for v in vulnerabilities if v.fix])

        if self.backup and not self.dry_run:
            self._create_backups(fixable)

        fixed = 0
        for vuln in fixable:
            if self._apply_fix(vuln):
                vuln.fix.applied = True
                fixed += 1
                file_path = vuln.location.file_path
                if file_path not in self.fixed_files:
                    self.fixed_files[file_path] = []
                self.fixed_files[file_path].append(vuln.fix.description)
            else:
                self.skipped.append(vuln)

        manual_review = [
            v for v in vulnerabilities
            if v.fix and v.fix.manual_review_required
        ]
        self.skipped.extend(manual_review)

        return fixed, len(self.skipped)

    def _create_backups(self, vulnerabilities: List[Vulnerability]):
        """Create backup copies of files that will be modified."""
        files_to_backup = {v.location.file_path for v in vulnerabilities}
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        for rel_path in files_to_backup:
            src = self.project_path / rel_path
            if src.exists():
                dst = self.backup_dir / rel_path
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)

    def _apply_fix(self, vuln: Vulnerability) -> bool:
        """Apply a single fix using AST-safe indentation-preserving method."""
        from djangosentinel.fixers.ast_safe_fixer import ASTSafeFixer
        ast_fixer = ASTSafeFixer(
            str(self.project_path),
            dry_run=self.dry_run,
            backup=self.backup,
        )
        return ast_fixer.apply_fix(vuln)

    def generate_fix_report(self) -> str:
        """Generate a human-readable fix report."""
        lines = ["=" * 60, "AUTO-FIX REPORT", "=" * 60, ""]

        if self.dry_run:
            lines.append("MODE: DRY RUN (no files were modified)\n")

        if self.fixed_files:
            lines.append(f"✅ Fixed {sum(len(v) for v in self.fixed_files.values())} issues in {len(self.fixed_files)} files:\n")
            for file_path, fixes in self.fixed_files.items():
                lines.append(f"  📄 {file_path}")
                for fix_desc in fixes:
                    lines.append(f"     • {fix_desc}")
            lines.append("")

        if self.skipped:
            manual = [v for v in self.skipped if v.fix and v.fix.manual_review_required]
            auto_failed = [v for v in self.skipped if v.fix and not v.fix.manual_review_required]

            if manual:
                lines.append(f"⚠️  {len(manual)} issues require manual review:\n")
                for vuln in manual:
                    lines.append(f"  • [{vuln.severity.value}] {vuln.title}")
                    lines.append(f"    Location: {vuln.location}")
                    lines.append(f"    Fix hint: {vuln.fix.explanation}\n")

            if auto_failed:
                lines.append(f"❌ {len(auto_failed)} auto-fixes could not be applied:\n")
                for vuln in auto_failed:
                    lines.append(f"  • {vuln.title} @ {vuln.location}")

        if self.backup_dir.exists():
            lines.append(f"\n💾 Backups saved to: {self.backup_dir}")

        return "\n".join(lines)
