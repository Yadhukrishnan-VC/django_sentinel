"""
DjangoSentinel CLI — Enterprise AI Security Scanner for Python/Django
=====================================================================
Commands:
sentinel scan .                       Full scan (all scanners)
sentinel scan . --diff                Scan ONLY changed lines (git diff)
sentinel scan . --diff --base main    Changed lines vs branch
sentinel scan . --diff-file pr.patch  Scan a saved diff/patch file
sentinel scan . --fix --ai            Auto-fix + AI for complex issues
sentinel scan . --format html -o r    HTML report
sentinel scan . --format sarif -o r   SARIF for GitHub Code Scanning
sentinel scan . --pr-comment          Post results to GitHub PR
sentinel fix .                        Apply fixes only
sentinel explain views.py 42          AI explanation of a specific line
sentinel install-hooks                Install git pre-commit/pre-push hooks
"""

import argparse
import sys
import uuid
import time
from pathlib import Path

from dotenv import load_dotenv

from djangosentinel.models import ScanResult, Severity
from djangosentinel.scanners import (
    DjangoScanner, BusinessLogicScanner, DependencyScanner, ASTScanner,
    DiffScanner, GitDiffSource,
)
from djangosentinel.fixers import ContextAwareFixer
from djangosentinel.paths import is_excluded
from djangosentinel.reporters import (
    TerminalReporter, JSONReporter, HTMLReporter, SARIFReporter, DiffReporter
)
from djangosentinel.hooks import HookInstaller
from djangosentinel.analysis import (
    DataFlowTracker, apply_confidence_scores, deduplicate,
    filter_by_confidence,
)
from djangosentinel.cache import ScanCache


SEVERITY_ORDER = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
}

C = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
    "red":    "\033[91m",
    "yellow": "\033[33m",
    "green":  "\033[92m",
    "blue":   "\033[94m",
    "cyan":   "\033[96m",
}


def _c(color: str, text: str, no_color: bool = False) -> str:
    return text if no_color else f"{C.get(color, '')}{text}{C['reset']}"


def _step(icon: str, text: str, no_color: bool = False):
    print(f"  {icon}  {_c('dim', text, no_color)}")


def _header(no_color: bool = False):
    banner = (
        "\n  ╔══════════════════════════════════════════════════╗\n"
        "  ║       🛡️  DJANGOSENTINEL  v1.0.0                  ║\n"
        "  ║       Enterprise AI Security Scanner             ║\n"
        "  ╚══════════════════════════════════════════════════╝"
    )
    print(_c("cyan", banner, no_color))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="🛡️  DjangoSentinel — AI-Powered Security Scanner for Python/Django",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan modes:
sentinel scan .                       Full project scan (all files)
sentinel scan . --diff                Changed lines only (git diff HEAD)
sentinel scan . --diff --staged       Staged changes only (pre-commit)
sentinel scan . --diff --base main    Changes vs main branch (PR mode)
sentinel scan . --diff-file pr.patch  Scan a saved .diff / .patch file

Fix modes:
sentinel scan . --fix                 Rule-based auto-fix
sentinel scan . --fix --ai            Rule-based + AI complex fixes

Reports:
sentinel scan . --format html -o r.html
sentinel scan . --format sarif -o r.sarif   (GitHub Code Scanning)
sentinel scan . --format json -o r.json

CI gates:
sentinel scan . --fail-on critical         Exit 1 on CRITICAL (strict)
sentinel scan . --diff --fail-on high      PR gate: exit 1 on HIGH in diff

GitHub PR:
sentinel scan . --pr-comment               Post summary comment
sentinel scan . --pr-inline --pr-check     Inline annotations + Check Run

Other:
sentinel explain views.py 42              AI explanation of line 42
sentinel install-hooks                     Install pre-commit/pre-push hooks
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── scan ─────────────────────────────────────────────────────────────────
    scan_p = subparsers.add_parser("scan", help="Scan project for vulnerabilities")
    scan_p.add_argument("path", nargs="?", default=".", help="Project path (default: .)")

    # ── Output ───────────────────────────────────────────────────────────────
    scan_p.add_argument(
        "--format", choices=["terminal", "json", "html", "sarif"],
        default="terminal", help="Output format (default: terminal)",
    )
    scan_p.add_argument("-o", "--output", help="Save output to file")
    scan_p.add_argument("--no-color", action="store_true", help="Disable ANSI colours")

    # ── Diff / targeted scan ─────────────────────────────────────────────────
    diff_grp = scan_p.add_argument_group("Diff mode (scan only changed lines)")
    diff_grp.add_argument(
        "--diff", action="store_true",
        help="Scan ONLY lines changed in the current git diff (fastest, ideal for PRs)",
    )
    diff_grp.add_argument(
        "--staged", action="store_true",
        help="With --diff: scan staged changes only (default: unstaged + staged vs HEAD)",
    )
    diff_grp.add_argument(
        "--base", metavar="BRANCH_OR_SHA",
        help="With --diff: compare against this branch or commit (e.g. main, origin/main, abc1234)",
    )
    diff_grp.add_argument(
        "--head", metavar="SHA",
        help="With --diff --base: end of range (default: current HEAD)",
    )
    diff_grp.add_argument(
        "--diff-file", metavar="FILE.diff",
        help="Scan a saved .diff or .patch file instead of running git diff",
    )

    # ── Fix modes ─────────────────────────────────────────────────────────────
    fix_grp = scan_p.add_argument_group("Fix options")
    fix_grp.add_argument("--fix", action="store_true", help="Auto-fix safe vulnerabilities")
    fix_grp.add_argument("--dry-run", action="store_true", help="Preview fixes without applying")

    # ── AI options ────────────────────────────────────────────────────────────
    ai_grp = scan_p.add_argument_group("AI options (need ANTHROPIC_API_KEY, OPENAI_API_KEY or GOOGLE_API_KEY)")
    ai_grp.add_argument(
        "--ai", action="store_true",
        help="Enable AI-powered fixes and explanations",
    )
    ai_grp.add_argument(
        "--ai-deep", action="store_true",
        help="Run AI pattern scanner on every file (catches unknown patterns, slower)",
    )
    ai_grp.add_argument(
        "--ai-explain", action="store_true",
        help="Generate AI explanation for every finding",
    )

    # ── Scanner toggles ───────────────────────────────────────────────────────
    skip_grp = scan_p.add_argument_group("Scanner toggles")
    skip_grp.add_argument("--skip-deps",  action="store_true", help="Skip dependency CVE scan")
    skip_grp.add_argument("--skip-logic", action="store_true", help="Skip business logic scan")
    skip_grp.add_argument("--skip-ast",   action="store_true", help="Skip AST structural scan")
    skip_grp.add_argument("--skip-taint", action="store_true", help="Skip data-flow taint analysis")

    # ── Performance / cache ────────────────────────────────────────────────
    perf_grp = scan_p.add_argument_group("Performance")
    perf_grp.add_argument("--no-cache", action="store_true",
                            help="Reserved: the file-hash cache is not used by scans yet, so every scan is a full scan")
    perf_grp.add_argument("--clear-cache", action="store_true",
                            help="Clear the scan cache and exit")
    perf_grp.add_argument("--min-confidence", type=float, default=0.0, metavar="0.0-1.0",
                            help="Minimum confidence threshold to report findings (e.g. 0.65)")

    # ── CI gate ───────────────────────────────────────────────────────────────
    scan_p.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "low"],
        help="Exit 1 if any unfixed finding at this severity or above",
    )

    # ── GitHub PR integration ─────────────────────────────────────────────────
    gh_grp = scan_p.add_argument_group("GitHub PR integration (require GITHUB_TOKEN)")
    gh_grp.add_argument("--pr-comment", action="store_true", help="Post summary PR comment")
    gh_grp.add_argument("--pr-inline",  action="store_true", help="Post inline PR annotations")
    gh_grp.add_argument("--pr-check",   action="store_true", help="Create GitHub Check Run")
    gh_grp.add_argument("--gh-token",   help="GitHub token (default: $GITHUB_TOKEN)")
    gh_grp.add_argument("--gh-repo",    help="owner/repo (default: $GITHUB_REPOSITORY)")
    gh_grp.add_argument("--gh-pr",      type=int, help="PR number (default: auto-detect)")
    gh_grp.add_argument("--gh-sha",     help="Commit SHA (default: $GITHUB_SHA)")

    # ── Internal ──────────────────────────────────────────────────────────────
    scan_p.add_argument("--staged-only", nargs="*", help=argparse.SUPPRESS)

    # ── fix ───────────────────────────────────────────────────────────────────
    fix_p = subparsers.add_parser("fix", help="Scan and apply all fixes")
    fix_p.add_argument("path", nargs="?", default=".")
    fix_p.add_argument("--dry-run", action="store_true")
    fix_p.add_argument("--no-backup", action="store_true")
    fix_p.add_argument("--ai", action="store_true", help="Use AI for complex fixes")
    fix_p.add_argument("--no-color", action="store_true")

    # ── explain ───────────────────────────────────────────────────────────────
    explain_p = subparsers.add_parser("explain", help="AI explanation of a specific line")
    explain_p.add_argument("file", help="Source file path")
    explain_p.add_argument("line", type=int, help="Line number")
    explain_p.add_argument("--no-color", action="store_true")

    # ── hooks ─────────────────────────────────────────────────────────────────
    hook_p = subparsers.add_parser("install-hooks", help="Install git pre-commit/pre-push hooks")
    hook_p.add_argument("path", nargs="?", default=".")
    hook_p.add_argument(
        "--hooks", nargs="+",
        choices=["pre-commit", "pre-push"],
        default=["pre-commit", "pre-push"],
    )

    unhook_p = subparsers.add_parser("uninstall-hooks", help="Remove installed hooks")
    unhook_p.add_argument("path", nargs="?", default=".")

    status_p = subparsers.add_parser("hook-status", help="Check hook installation status")
    status_p.add_argument("path", nargs="?", default=".")

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# Diff-mode scan
# ─────────────────────────────────────────────────────────────────────────────

def run_diff_scan(args) -> tuple:
    """
    Run a diff-scoped scan: only lines that appear in the git diff are checked.

    Returns (ScanResult, diff_summary_dict)
    """
    project_path = str(Path(args.path).resolve())
    no_color = getattr(args, "no_color", False)
    is_terminal = getattr(args, "format", "terminal") == "terminal"

    if is_terminal:
        _header(no_color)

    # ── Determine diff source ─────────────────────────────────────────────────
    diff_source = GitDiffSource(project_path)

    if getattr(args, "diff_file", None):
        _step("📂", f"Reading diff from file: {args.diff_file}", no_color)
        diff_text = diff_source.get_diff(mode="file", diff_file=args.diff_file)
    elif getattr(args, "staged", False):
        _step("📋", "Scanning staged changes (git diff --staged)...", no_color)
        diff_text = diff_source.get_diff(mode="staged")
    elif getattr(args, "base", None):
        base = args.base
        head = getattr(args, "head", "") or ""
        mode = "range" if head else "branch"
        label = f"{base}..{head}" if head else f"vs {base}"
        _step("🌿", f"Scanning changes {label}...", no_color)
        diff_text = diff_source.get_diff(mode=mode, base=base, head=head)
    else:
        _step("🔄", "Scanning changed lines (git diff HEAD)...", no_color)
        diff_text = diff_source.get_diff(mode="head")

    if not diff_text.strip():
        print(_c("yellow", "\n  ⚠️  No diff found. Nothing to scan.", no_color))
        print("  Tip: Make some changes or specify --base <branch>\n")
        empty_result = ScanResult(
            scan_id=str(uuid.uuid4())[:12],
            project_path=project_path,
            files_scanned=0,
            vulnerabilities=[],
            scan_duration_seconds=0.0,
        )
        return empty_result, {}

    # ── AI engine setup ──────────────────────────────────────────────────────
    use_ai = getattr(args, "ai", False) or getattr(args, "ai_deep", False)
    ai_fix_engine = None
    ai_explainer = None
    ai_pattern_scanner = None

    if use_ai:
        from djangosentinel.ai_engine import AIFixEngine, AIExplainer, AIPatternScanner
        from djangosentinel.ai_model_providers import refresh_ai_provider
        refresh_ai_provider()  # pick Anthropic / OpenAI / Gemini from the environment
        ai_fix_engine = AIFixEngine()
        ai_explainer = AIExplainer()
        if getattr(args, "ai_deep", False):
            ai_pattern_scanner = AIPatternScanner()
        if is_terminal:
            status = (
                _c("green", "✅ AI ready", no_color) if ai_fix_engine.available
                else _c("yellow", "⚠️  No AI API key (ANTHROPIC_API_KEY, OPENAI_API_KEY or GOOGLE_API_KEY)", no_color)
            )
            print(f"  🤖 AI Engine: {status}\n")

    # ── Run diff scanner ──────────────────────────────────────────────────────
    start = time.time()

    scanner = DiffScanner(
        project_path=project_path,
        diff_text=diff_text,
        skip_ast=getattr(args, "skip_ast", False),
        skip_logic=getattr(args, "skip_logic", False),
        skip_deps=getattr(args, "skip_deps", False),
    )

    diff_sum = scanner.diff_summary()
    total_files = diff_sum.get("total_changed_files", 0)
    total_lines = diff_sum.get("total_added_lines", 0)

    if is_terminal:
        _step("🔍", f"Scanning {total_files} changed files ({total_lines} added lines)...", no_color)

    all_vulns = scanner.scan()

    # ── AI pattern scan on diff files ─────────────────────────────────────────
    if ai_pattern_scanner and ai_pattern_scanner.available:
        if is_terminal:
            _step("🤖", "Running AI pattern scanner on changed files...", no_color)
        for df in scanner.diff_files:
            if not df.path.endswith(".py"):
                continue
            full_path = Path(project_path) / df.path
            if not full_path.exists():
                continue
            try:
                source = full_path.read_text(encoding="utf-8", errors="ignore")
                ai_vulns = ai_pattern_scanner.scan_file(df.path, source)
                # Filter AI findings to changed lines too
                added = set(df.all_added_lines.keys())
                for v in ai_vulns:
                    if v.location.line_number in added or df.is_new_file:
                        v.metadata["diff_detected"] = True
                        all_vulns.append(v)
            except Exception:
                continue

    # ── AI explanations ──────────────────────────────────────────────────────
    if ai_explainer and ai_explainer.available and getattr(args, "ai_explain", False):
        if is_terminal:
            _step("💬", "Generating AI explanations...", no_color)
        for v in all_vulns:
            try:
                expl = ai_explainer.explain(v)
                if expl:
                    v.metadata["ai_explanation"] = expl
            except Exception:
                pass

    duration = time.time() - start

    # ── Deduplication + confidence scoring ────────────────────────────────────
    all_vulns = deduplicate(all_vulns)
    all_vulns = apply_confidence_scores(all_vulns)

    min_conf = getattr(args, "min_confidence", 0.0)
    if min_conf > 0.0:
        all_vulns = filter_by_confidence(all_vulns, min_confidence=min_conf)

    result = ScanResult(
        scan_id=str(uuid.uuid4())[:12],
        project_path=project_path,
        files_scanned=total_files,
        vulnerabilities=all_vulns,
        scan_duration_seconds=duration,
    )

    if is_terminal:
        print()
        _step(
            "✅",
            f"Diff scan complete: {total_files} files, {total_lines} lines checked, "
            f"{len(all_vulns)} findings — {duration:.2f}s",
            no_color,
        )
        print()

    # ── Fix phase ─────────────────────────────────────────────────────────────
    if getattr(args, "fix", False) and all_vulns:
        if is_terminal:
            _step("🔧", "Applying fixes to changed files...", no_color)
        fixer = ContextAwareFixer(
            project_path,
            ai_engine=ai_fix_engine,
            dry_run=getattr(args, "dry_run", False),
            backup=True,
        )
        rule_fixed, ai_fixed, manual = fixer.fix_all(all_vulns)
        if is_terminal:
            print(fixer.generate_report(rule_fixed, ai_fixed, manual))

    return result, diff_sum


# ─────────────────────────────────────────────────────────────────────────────
# Full scan (existing behaviour, unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def run_full_scan(args) -> ScanResult:
    project_path = str(Path(args.path).resolve())
    no_color = getattr(args, "no_color", False)
    use_ai = getattr(args, "ai", False) or getattr(args, "ai_deep", False)
    is_terminal = getattr(args, "format", "terminal") == "terminal"

    if is_terminal:
        _header(no_color)

    ai_fix_engine = None
    ai_explainer = None
    ai_pattern_scanner = None

    if use_ai:
        from djangosentinel.ai_engine import AIFixEngine, AIExplainer, AIPatternScanner
        from djangosentinel.ai_model_providers import refresh_ai_provider
        refresh_ai_provider()  # pick Anthropic / OpenAI / Gemini from the environment
        ai_fix_engine = AIFixEngine()
        ai_explainer = AIExplainer()
        if getattr(args, "ai_deep", False):
            ai_pattern_scanner = AIPatternScanner()
        if is_terminal:
            status = (
                _c("green", "✅ AI ready", no_color)
                if ai_fix_engine.available
                else _c("yellow", "⚠️  No AI API key (ANTHROPIC_API_KEY, OPENAI_API_KEY or GOOGLE_API_KEY) — AI disabled", no_color)
            )
            print(f"  🤖 AI Engine: {status}\n")

    scan_id = str(uuid.uuid4())[:12]
    all_vulns = []
    errors = []
    files_scanned = 0
    start = time.time()

    for f in Path(project_path).rglob("*.py"):
        if not is_excluded(f, project_path):
            files_scanned += 1
    for f in Path(project_path).rglob("*.html"):
        if not is_excluded(f, project_path):
            files_scanned += 1

    # ── Cache housekeeping (--clear-cache) ────────────────────────────────────
    if getattr(args, "clear_cache", False):
        ScanCache(project_path).clear()
        print(_c("green", "  ✅ Scan cache cleared.", no_color))
        sys.exit(0)

    def _run_ast_scanner():
        ast_scanner = ASTScanner(project_path)
        found = ast_scanner.scan()
        errors.extend(ast_scanner.parse_errors)
        return found

    scanners_to_run = [
        ("🔍 Django Scanner",         lambda: DjangoScanner(project_path).scan(),          True),
        ("📐 AST Structural Scanner", _run_ast_scanner,                                    not getattr(args, "skip_ast", False)),
        ("🧠 Business Logic Scanner", lambda: BusinessLogicScanner(project_path).scan(),   not getattr(args, "skip_logic", False)),
        ("📦 Dependency CVE Scanner", lambda: DependencyScanner(project_path).scan(),      not getattr(args, "skip_deps", False)),
    ]

    for label, fn, enabled in scanners_to_run:
        if not enabled:
            continue
        if is_terminal:
            _step("🔄", f"Running {label}...", no_color)
        try:
            all_vulns.extend(fn())
        except Exception as e:
            errors.append(f"{label}: {e}")

    # ── Taint / data-flow analysis ────────────────────────────────────────────
    if not getattr(args, "skip_taint", False):
        if is_terminal:
            _step("🔗", "Running data-flow taint analysis...", no_color)
        try:
            tracker = DataFlowTracker(project_path)
            taint_flows = tracker.analyze_project()
            import uuid as _uuid
            for flow in taint_flows:
                if not flow.sanitized:
                    sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                                "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
                    sev = sev_map.get(flow.vuln_info.get("severity", "MEDIUM"), Severity.MEDIUM)
                    from djangosentinel.models import Vulnerability as _V, VulnCategory as _VC, CodeLocation as _CL
                    all_vulns.append(_V(
                        vuln_id=str(_uuid.uuid4())[:8],
                        title=f"[Taint] {flow.vuln_info['vuln']} — {flow.source_var} → {flow.sink_name}",
                        category=_VC.INJECTION,
                        severity=sev,
                        location=_CL(flow.file_path, flow.sink_line),
                        description=(
                            f"User-controlled data from {flow.source_var} flows to "
                            f"{flow.sink_name} (line {flow.sink_line}). "
                            f"Propagation: {' → '.join(flow.propagation_path[-3:])}"
                        ),
                        owasp_ref="A03:2021 – Injection",
                        cwe_id=flow.vuln_info.get("cwe", "CWE-89"),
                        metadata={"source": "taint_tracker", "confidence": flow.confidence},
                    ))
        except Exception as e:
            errors.append(f"Taint analysis: {e}")

    if ai_pattern_scanner and ai_pattern_scanner.available:
        if is_terminal:
            _step("🤖", "Running AI pattern scanner (deep mode)...", no_color)
        for py_file in Path(project_path).rglob("*.py"):
            if is_excluded(py_file, project_path):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                rel = str(py_file.relative_to(project_path))
                all_vulns.extend(ai_pattern_scanner.scan_file(rel, source))
            except Exception:
                continue

    if ai_explainer and ai_explainer.available and getattr(args, "ai_explain", False):
        if is_terminal:
            _step("💬", "Generating AI explanations...", no_color)
        for v in all_vulns:
            try:
                expl = ai_explainer.explain(v)
                if expl:
                    v.metadata["ai_explanation"] = expl
            except Exception:
                pass

    duration = time.time() - start

    # ── Post-processing: deduplicate + confidence score + filter ──────────────
    if is_terminal:
        _step("🔬", "Deduplicating and scoring findings...", no_color)

    # Build source map for confidence scoring (file → source text)
    source_map = {}
    try:
        for py_file in Path(project_path).rglob("*.py"):
            rel = str(py_file.relative_to(project_path))
            if not is_excluded(py_file, project_path):
                source_map[rel] = py_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        pass

    all_vulns = deduplicate(all_vulns)
    all_vulns = apply_confidence_scores(all_vulns, source_map=source_map)

    min_conf = getattr(args, "min_confidence", 0.0)
    if min_conf > 0.0:
        before = len(all_vulns)
        all_vulns = filter_by_confidence(all_vulns, min_confidence=min_conf)
        if is_terminal:
            filtered = before - len(all_vulns)
            if filtered:
                _step("🔽", f"Filtered {filtered} low-confidence findings (min={min_conf})", no_color)

    result = ScanResult(
        scan_id=scan_id,
        project_path=project_path,
        files_scanned=files_scanned,
        vulnerabilities=all_vulns,
        scan_duration_seconds=duration,
        errors=errors,
    )

    if is_terminal:
        print()
        _step(
            "✅",
            f"Scan complete: {files_scanned} files · {len(all_vulns)} findings · {duration:.2f}s",
            no_color,
        )
        print()

    if getattr(args, "fix", False) and all_vulns:
        if is_terminal:
            _step("🔧", "Applying fixes...", no_color)
        fixer = ContextAwareFixer(
            project_path,
            ai_engine=ai_fix_engine,
            dry_run=getattr(args, "dry_run", False),
            backup=True,
        )
        rule_fixed, ai_fixed, manual = fixer.fix_all(all_vulns)
        if is_terminal:
            print(fixer.generate_report(rule_fixed, ai_fixed, manual))

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Command handlers
# ─────────────────────────────────────────────────────────────────────────────

def _validate_project_dir(path_str: str, no_color: bool = False) -> None:
    """
    Exit with status 2 if the scan target is missing or not a directory.

    Without this check a mistyped path scans zero files and reports
    "No vulnerabilities found", which would let a broken CI step pass.
    """
    p = Path(path_str)
    if not p.exists():
        print(_c("red", f"  ❌ Path not found: {path_str}", no_color), file=sys.stderr)
        sys.exit(2)
    if not p.is_dir():
        print(
            _c("red", f"  ❌ Not a directory: {path_str} (pass the project folder to scan)", no_color),
            file=sys.stderr,
        )
        sys.exit(2)


def cmd_scan(args):
    no_color = getattr(args, "no_color", False)
    use_diff = getattr(args, "diff", False) or getattr(args, "diff_file", None)
    _validate_project_dir(getattr(args, "path", "."), no_color)

    # Handle --clear-cache before any scan
    if getattr(args, "clear_cache", False):
        path = str(Path(getattr(args, "path", ".")).resolve())
        ScanCache(path).clear()
        print(_c("green", "  ✅ Scan cache cleared.", no_color))
        sys.exit(0)

    # ── Choose scan mode ──────────────────────────────────────────────────────
    diff_summary = {}
    if use_diff:
        result, diff_summary = run_diff_scan(args)
    else:
        result = run_full_scan(args)

    # ── Generate report ───────────────────────────────────────────────────────
    fmt = getattr(args, "format", "terminal")

    if use_diff:
        if fmt == "json":
            reporter = DiffReporter(no_color=no_color, diff_summary=diff_summary)
            output = reporter.report_json(result)
        elif fmt == "html":
            # HTML reporter works fine for diff results too
            reporter = HTMLReporter()
            output = reporter.report(result)
        elif fmt == "sarif":
            reporter = SARIFReporter()
            output = reporter.report(result)
        else:
            reporter = DiffReporter(no_color=no_color, diff_summary=diff_summary)
            output = reporter.report(result)
    else:
        if fmt == "terminal":
            output = TerminalReporter(no_color=no_color).report(result)
        elif fmt == "json":
            output = JSONReporter().report(result)
        elif fmt == "html":
            output = HTMLReporter().report(result)
        elif fmt == "sarif":
            output = SARIFReporter().report(result)
        else:
            output = TerminalReporter(no_color=no_color).report(result)

    # ── Write / print ─────────────────────────────────────────────────────────
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(_c("green", f"\n  📄 Report saved: {args.output}", no_color))
    else:
        print(output)

    # ── GitHub PR integration ─────────────────────────────────────────────────
    do_pr = getattr(args, "pr_comment", False)
    do_inline = getattr(args, "pr_inline", False)
    do_check = getattr(args, "pr_check", False)

    if do_pr or do_inline or do_check:
        from djangosentinel.github_integration import GitHubPRIntegration
        from djangosentinel.ai_engine import PRReviewSummarizer

        gh = GitHubPRIntegration(
            token=getattr(args, "gh_token", None),
            repo=getattr(args, "gh_repo", None),
            pr_number=getattr(args, "gh_pr", None),
            commit_sha=getattr(args, "gh_sha", None),
        )

        if not gh.available:
            print(_c("yellow", "\n  ⚠️  GitHub integration unavailable — set GITHUB_TOKEN", no_color))
        else:
            summarizer = None
            if getattr(args, "ai", False):
                summarizer = PRReviewSummarizer()

            if do_pr:
                ok = gh.post_summary_comment(result, summarizer=summarizer)
                print(f"\n  {'✅' if ok else '❌'} PR comment {'posted' if ok else 'failed'}")
            if do_inline:
                count = gh.post_inline_review(result)
                print(f"\n  📌 {count} inline annotations posted")
            if do_check:
                ok = gh.create_check_run(result)
                print(f"\n  {'✅' if ok else '❌'} Check run {'created' if ok else 'failed'}")

    # ── CI exit code ──────────────────────────────────────────────────────────
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        sev_levels = list(SEVERITY_ORDER.values())
        threshold_idx = sev_levels.index(threshold)
        for v in result.vulnerabilities:
            if v.fix and v.fix.applied:
                continue
            if sev_levels.index(v.severity) <= threshold_idx:
                sys.exit(1)

    sys.exit(0)


def cmd_fix(args):
    args.fix = True
    args.diff = False
    args.diff_file = None
    args.skip_deps = False
    args.skip_logic = False
    args.skip_ast = False
    args.fail_on = None
    args.format = "terminal"
    args.output = None
    args.pr_comment = False
    args.pr_inline = False
    args.pr_check = False
    args.ai_explain = False
    args.ai_deep = False
    args.staged = False
    args.base = None
    args.head = None
    cmd_scan(args)


def cmd_explain(args):
    no_color = getattr(args, "no_color", False)
    _header(no_color)

    from djangosentinel.ai_engine import AIExplainer
    from djangosentinel.models import Vulnerability, VulnCategory, Severity, CodeLocation

    from djangosentinel.ai_model_providers import refresh_ai_provider
    refresh_ai_provider()
    explainer = AIExplainer()

    if not explainer.available:
        print(_c("yellow", "  ⚠️  No AI API key set (ANTHROPIC_API_KEY, OPENAI_API_KEY or GOOGLE_API_KEY). Cannot generate AI explanation.", no_color))
        sys.exit(1)

    try:
        source = Path(args.file).read_text(encoding="utf-8", errors="ignore")
        lines = source.splitlines()
        lineno = args.line
        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""

        start = max(0, lineno - 10)
        end = min(len(lines), lineno + 10)
        context = "\n".join(
            f"{start + i + 1:4d} | {l}"
            for i, l in enumerate(lines[start:end])
        )

        stub = Vulnerability(
            vuln_id="explain",
            title="Code Review",
            category=VulnCategory.MISCONFIG,
            severity=Severity.INFO,
            location=CodeLocation(args.file, lineno, snippet=snippet),
            description="",
            cwe_id="",
        )

        print(f"\n  {_c('bold', 'File:', no_color)} {args.file}:{lineno}")
        print(f"  {_c('bold', 'Code:', no_color)} {snippet}\n")
        print(f"  {_c('cyan', '🤖 Generating AI security analysis...', no_color)}\n")

        explanation = explainer.explain(stub, code_context=context)

        if explanation:
            print(_c("bold", "  Security Analysis:", no_color))
            print()
            for line in explanation.splitlines():
                print(f"  {line}")
        else:
            print("  No security concerns identified for this specific line.")

        print()

    except FileNotFoundError:
        print(f"  ❌ File not found: {args.file}")
        sys.exit(1)


def cmd_install_hooks(args):
    path = str(Path(args.path).resolve())
    installer = HookInstaller(path)
    results = installer.install(args.hooks)

    print("\n  🛡️  DjangoSentinel Hook Installer")
    print("  " + "═" * 44)
    for hook, res in results.items():
        if isinstance(res, dict):
            icon = "✅" if res.get("success") else "❌"
            msg = res.get("path", res.get("error", ""))
            print(f"  {icon} {hook}: {msg}")

    print("\n  ✨ Hooks installed — commits and pushes are now protected.")
    print("  💡 Tip: sentinel scan . --diff   scans only your staged changes.\n")


def cmd_uninstall_hooks(args):
    path = str(Path(args.path).resolve())
    installer = HookInstaller(path)
    results = installer.uninstall()
    print("\n  🛡️  DjangoSentinel: Hooks uninstalled.\n")
    for k, v in results.items():
        print(f"  • {k}: {v}")
    print()


def cmd_hook_status(args):
    path = str(Path(args.path).resolve())
    installer = HookInstaller(path)
    status = installer.status()
    print("\n  🛡️  DjangoSentinel Hook Status")
    print("  " + "═" * 36)
    for hook, info in status.items():
        installed = info.get("installed", False)
        print(f"  {'✅' if installed else '❌'} {hook}: {'installed' if installed else 'not installed'}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def _make_console_safe():
    """Replace characters the terminal cannot encode instead of crashing."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main():
    _make_console_safe()
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "scan":             cmd_scan,
        "fix":              cmd_fix,
        "explain":          cmd_explain,
        "install-hooks":    cmd_install_hooks,
        "uninstall-hooks":  cmd_uninstall_hooks,
        "hook-status":      cmd_hook_status,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
