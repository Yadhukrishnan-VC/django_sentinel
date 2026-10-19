"""
Git Diff Scanner — DjangoSentinel
===================================
Scans ONLY the lines that changed in a git diff, not the entire file.

This is fundamentally different from --staged-only (which scans the full
content of staged files). The diff scanner:

1. Parses unified diff format (git diff, git diff HEAD, PR diffs)
2. Extracts only the ADDED lines (+) from each hunk
3. Runs all scanners on those lines in context
4. Maps findings back to the actual file:line positions
5. Filters out findings on lines that were NOT changed

Why this matters:
- In a PR with 10,000 lines of existing code and 50 changed lines,
    you only want to know about security issues IN THE CHANGE, not the
    entire legacy codebase.
- Makes the diff scan extremely fast (sub-second on most PRs).
- Reduces noise — reviewers see only what THIS change introduces.

Supports:
- git diff                  (unstaged changes vs index)
- git diff --staged         (staged changes vs HEAD)
- git diff HEAD             (all changes vs HEAD)
- git diff <branch>         (changes vs a branch)
- git diff <sha1> <sha2>    (changes between commits)
- Piped diff files          (sentinel scan --diff <file.diff>)
- GitHub PR diffs (fetched via API)
"""

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Set

from djangosentinel.models import (
    Vulnerability
)


# ─────────────────────────────────────────────────────────────────────────────
# Diff data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DiffHunk:
    """One @@ hunk inside a diff file section."""
    start_line: int          # line number in the new file where this hunk starts
    lines: List[str]         # ALL lines in the hunk (context + added + removed)
    added_line_numbers: Set[int]  # which line numbers (new file) were ADDED


@dataclass
class DiffFile:
    """One file's worth of changes extracted from a unified diff."""
    path: str                # relative path to the file
    is_new_file: bool = False
    is_deleted: bool = False
    hunks: List[DiffHunk] = field(default_factory=list)

    @property
    def all_added_lines(self) -> Dict[int, str]:
        """Return {line_number: content} for every added line in this file."""
        result = {}
        for hunk in self.hunks:
            new_lineno = hunk.start_line
            for line in hunk.lines:
                if line.startswith("+") and not line.startswith("+++"):
                    result[new_lineno] = line[1:]  # strip the leading +
                    new_lineno += 1
                elif line.startswith("-"):
                    pass  # removed lines don't advance new-file counter
                else:
                    new_lineno += 1  # context lines advance both
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Unified diff parser
# ─────────────────────────────────────────────────────────────────────────────

class DiffParser:
    """Parses unified diff text into DiffFile objects."""

    # Matches: @@ -old_start,old_count +new_start,new_count @@
    HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    def parse(self, diff_text: str) -> List[DiffFile]:
        """Parse unified diff text, return list of DiffFile objects."""
        files: List[DiffFile] = []
        current_file: Optional[DiffFile] = None
        current_hunk: Optional[DiffHunk] = None
        new_lineno = 0
        _next_is_new = False   # set when we see --- /dev/null before +++ b/
        _next_is_deleted = False

        for raw_line in diff_text.splitlines():
            # New file section header
            if raw_line.startswith("diff --git "):
                if current_hunk and current_file:
                    current_file.hunks.append(current_hunk)
                if current_file:
                    files.append(current_file)
                current_file = None
                current_hunk = None
                _next_is_new = False
                _next_is_deleted = False
                continue

            # +++ b/path  →  this is the destination file path
            if raw_line.startswith("+++ b/"):
                path = raw_line[6:].strip()
                current_file = DiffFile(
                    path=path,
                    is_new_file=_next_is_new,
                    is_deleted=_next_is_deleted,
                )
                _next_is_new = False
                _next_is_deleted = False
                continue

            if raw_line.startswith("+++ /dev/null"):
                _next_is_deleted = True
                continue

            # --- /dev/null  →  source is /dev/null, so this is a new file
            if raw_line.startswith("--- /dev/null"):
                if current_file:
                    current_file.is_new_file = True
                else:
                    _next_is_new = True
                continue

            # +++ /dev/null  →  destination is /dev/null, so file is deleted
            if raw_line.startswith("+++ /dev/null"):
                if current_file:
                    current_file.is_deleted = True
                else:
                    _next_is_deleted = True
                continue

            if raw_line.startswith("new file"):
                if current_file:
                    current_file.is_new_file = True
                else:
                    _next_is_new = True
                continue

            # Hunk header
            hunk_match = self.HUNK_HEADER.match(raw_line)
            if hunk_match:
                if current_hunk and current_file:
                    current_file.hunks.append(current_hunk)
                new_lineno = int(hunk_match.group(1))
                current_hunk = DiffHunk(
                    start_line=new_lineno,
                    lines=[],
                    added_line_numbers=set(),
                )
                continue

            # Hunk content lines
            if current_hunk is not None and current_file is not None:
                if raw_line.startswith("+") and not raw_line.startswith("+++"):
                    current_hunk.lines.append(raw_line)
                    current_hunk.added_line_numbers.add(new_lineno)
                    new_lineno += 1
                elif raw_line.startswith("-") and not raw_line.startswith("---"):
                    current_hunk.lines.append(raw_line)
                    # removed lines: don't advance new-file counter
                else:
                    current_hunk.lines.append(raw_line)
                    new_lineno += 1

        # Flush last hunk/file
        if current_hunk and current_file:
            current_file.hunks.append(current_hunk)
        if current_file:
            files.append(current_file)

        return [f for f in files if not f.is_deleted]


# ─────────────────────────────────────────────────────────────────────────────
# Git diff source
# ─────────────────────────────────────────────────────────────────────────────

class GitDiffSource:
    """Fetches git diff text from various sources."""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    def get_diff(
        self,
        mode: str = "staged",
        base: str = "",
        head: str = "",
        diff_file: str = "",
    ) -> str:
        """
        Get unified diff text.

        Args:
            mode:      'staged', 'unstaged', 'head', 'branch', 'file', 'range'
            base:      base branch/SHA (for 'branch' or 'range' mode)
            head:      head SHA (for 'range' mode)
            diff_file: path to a .diff/.patch file (for 'file' mode)
        """
        if mode == "file":
            return self._from_file(diff_file)

        return self._from_git(mode, base, head)

    def _from_git(self, mode: str, base: str, head: str) -> str:
        """Run git diff and capture output."""
        if mode == "staged":
            cmd = ["git", "diff", "--staged", "--unified=3"]
        elif mode == "unstaged":
            cmd = ["git", "diff", "--unified=3"]
        elif mode == "head":
            cmd = ["git", "diff", "HEAD", "--unified=3"]
        elif mode == "branch" and base:
            cmd = ["git", "diff", base, "--unified=3"]
        elif mode == "range" and base and head:
            cmd = ["git", "diff", base, head, "--unified=3"]
        else:
            # Default: everything changed (staged + unstaged)
            cmd = ["git", "diff", "HEAD", "--unified=3"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.project_path),
                timeout=30,
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def _from_file(self, path: str) -> str:
        """Read diff from a .diff or .patch file."""
        try:
            return Path(path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def get_staged_files(self) -> List[str]:
        """Return list of staged file paths."""
        try:
            result = subprocess.run(
                ["git", "diff", "--staged", "--name-only"],
                capture_output=True, text=True,
                cwd=str(self.project_path), timeout=10,
            )
            return [l.strip() for l in result.stdout.splitlines() if l.strip()]
        except Exception:
            return []

    def get_changed_files_vs_branch(self, branch: str = "main") -> List[str]:
        """Return files changed vs a given branch."""
        for b in [branch, "origin/" + branch]:
            try:
                result = subprocess.run(
                    ["git", "diff", b, "--name-only"],
                    capture_output=True, text=True,
                    cwd=str(self.project_path), timeout=10,
                )
                if result.returncode == 0:
                    return [l.strip() for l in result.stdout.splitlines() if l.strip()]
            except Exception:
                continue
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Diff-aware scanner
# ─────────────────────────────────────────────────────────────────────────────

class DiffScanner:
    """
    Runs all DjangoSentinel scanners but filters results to ONLY include
    findings on lines that appear in the diff (added/modified lines).

    This is the core of --diff mode. It:
        1. Parses the diff to know which lines changed
        2. For each changed file, reads the full current file content
        (so scanners have proper context for AST parsing)
        3. Runs all scanners on the full file
        4. Filters findings to only those on changed lines
        5. Annotates each finding with whether it's in the diff
    """

    SCANNED_EXTENSIONS = {".py", ".html", ".txt", ".toml", ".cfg"}

    def __init__(
        self,
        project_path: str,
        diff_text: str,
        skip_ast: bool = False,
        skip_logic: bool = False,
        skip_deps: bool = False,
    ):
        self.project_path = Path(project_path)
        self.diff_text = diff_text
        self.skip_ast = skip_ast
        self.skip_logic = skip_logic
        self.skip_deps = skip_deps
        self.vulnerabilities: List[Vulnerability] = []

        # Parse the diff upfront
        parser = DiffParser()
        self.diff_files: List[DiffFile] = parser.parse(diff_text)

        # Build lookup: file_path → set of added line numbers
        # DiffFile.added_line_numbers comes from aggregating all its hunks
        self.changed_lines: Dict[str, Set[int]] = {
            df.path: set(df.all_added_lines.keys())
            for df in self.diff_files
            if self._is_scannable(df.path)
        }

    def _is_scannable(self, path: str) -> bool:
        return Path(path).suffix in self.SCANNED_EXTENSIONS

    def scan(self) -> List[Vulnerability]:
        """
        Full scan filtered to diff lines only.
        Returns only findings on changed lines.
        """
        from djangosentinel.scanners.django_scanner import DjangoScanner
        from djangosentinel.scanners.business_logic_scanner import BusinessLogicScanner
        from djangosentinel.scanners.dependency_scanner import DependencyScanner

        self.vulnerabilities = []

        # Scan each changed file individually
        for diff_file in self.diff_files:
            if not self._is_scannable(diff_file.path):
                continue

            full_path = self.project_path / diff_file.path
            if not full_path.exists():
                continue

            try:
                source = full_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            added_lines = set(diff_file.all_added_lines.keys())
            if not added_lines and not diff_file.is_new_file:
                continue

            # Run all enabled scanners on the full file
            file_vulns: List[Vulnerability] = []

            # Django pattern scanner
            ds = DjangoScanner(str(self.project_path))
            try:
                rel = diff_file.path
                if diff_file.path.endswith(".py"):
                    if ds._is_settings_file(full_path):
                        ds._scan_settings(source, rel)
                    ds._scan_views(source, rel, full_path)
                    ds._scan_models(source, rel)
                    ds._scan_urls(source, rel)
                    ds._scan_templates_in_python(source, rel)
                    ds._scan_hardcoded_secrets(source, rel)
                    ds._scan_dangerous_functions(source, rel)
                elif diff_file.path.endswith(".html"):
                    ds._scan_templates(source, rel)
                file_vulns.extend(ds.vulnerabilities)
            except Exception:
                pass

            # AST scanner
            if not self.skip_ast and diff_file.path.endswith(".py"):
                try:
                    import ast
                    tree = ast.parse(source)
                    from djangosentinel.scanners.ast_scanner import _SecurityVisitor
                    visitor = _SecurityVisitor(source, diff_file.path)
                    visitor.visit(tree)
                    file_vulns.extend(visitor.vulnerabilities)
                except Exception:
                    pass

            # Business logic scanner
            if not self.skip_logic and diff_file.path.endswith(".py"):
                bl = BusinessLogicScanner(str(self.project_path))
                try:
                    bl._scan_race_conditions(source, diff_file.path)
                    bl._scan_financial_operations(source, diff_file.path)
                    bl._scan_privilege_escalation(source, diff_file.path)
                    bl._scan_workflow_bypass(source, diff_file.path)
                    bl._scan_negative_values(source, diff_file.path)
                    bl._scan_coupon_abuse(source, diff_file.path)
                    bl._scan_pagination_disclosure(source, diff_file.path)
                    bl._scan_time_based_logic(source, diff_file.path)
                    file_vulns.extend(bl.vulnerabilities)
                except Exception:
                    pass

            # Filter: only keep findings on changed lines
            # For new files: keep everything; for modified: only changed lines
            if diff_file.is_new_file:
                filtered = file_vulns
            else:
                filtered = [
                    v for v in file_vulns
                    if v.location.line_number in added_lines
                ]

            # Tag each finding as diff-detected
            for v in filtered:
                v.metadata["diff_detected"] = True
                v.metadata["diff_line"] = v.location.line_number in added_lines

            self.vulnerabilities.extend(filtered)

        # Dependency scan is not line-filtered (whole file changes matter)
        if not self.skip_deps:
            dep_scanner = DependencyScanner(str(self.project_path))
            dep_vulns = dep_scanner.scan()
            # Only include if requirements file was in the diff
            changed_req_files = {
                df.path for df in self.diff_files
                if any(
                    kw in df.path
                    for kw in ["requirements", "Pipfile", "pyproject", "setup.py", "setup.cfg"]
                )
            }
            for dv in dep_vulns:
                if dv.location.file_path in changed_req_files:
                    dv.metadata["diff_detected"] = True
                    self.vulnerabilities.append(dv)

        return self.vulnerabilities

    def diff_summary(self) -> Dict:
        """Summary of what the diff contains."""
        py_files = [f for f in self.diff_files if f.path.endswith(".py")]
        html_files = [f for f in self.diff_files if f.path.endswith(".html")]
        total_added = sum(len(f.all_added_lines) for f in self.diff_files)

        return {
            "total_changed_files": len(self.diff_files),
            "python_files": len(py_files),
            "html_files": len(html_files),
            "total_added_lines": total_added,
            "files": [
                {
                    "path": f.path,
                    "added_lines": len(f.all_added_lines),
                    "is_new": f.is_new_file,
                }
                for f in self.diff_files
                if self._is_scannable(f.path)
            ],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Import guard for DependencyScanner (used inside DiffScanner)
# ─────────────────────────────────────────────────────────────────────────────
from typing import Dict
