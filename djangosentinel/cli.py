"""
DjangoSentinel CLI — Enterprise Security Scanner for Python/Django
Usage:
  sentinel scan <path> [options]
  sentinel fix <path> [options]
  sentinel install-hooks [path]
  sentinel uninstall-hooks [path]
  sentinel hook-status [path]
"""

import argparse
import sys
import os
import uuid
import time
from pathlib import Path

from djangosentinel.models import ScanResult, Severity
from djangosentinel.scanners import DjangoScanner, BusinessLogicScanner, DependencyScanner
from djangosentinel.fixers import AutoFixer
from djangosentinel.reporters import TerminalReporter, JSONReporter, HTMLReporter, SARIFReporter
from djangosentinel.hooks import HookInstaller


SEVERITY_ORDER = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="🛡️  DjangoSentinel — AI Security Assistant for Python/Django",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinel scan .                          # Scan current directory
  sentinel scan . --fix                    # Scan and auto-fix safe issues
  sentinel scan . --format json > report.json
  sentinel scan . --format html -o report.html
  sentinel scan . --format sarif -o results.sarif
  sentinel scan . --fail-on critical       # Exit 1 if any CRITICAL found
  sentinel fix . --dry-run                 # Preview fixes without applying
  sentinel install-hooks                   # Install git pre-commit hooks
  sentinel hook-status                     # Check hook installation status
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- scan ---
    scan_p = subparsers.add_parser("scan", help="Scan project for vulnerabilities")
    scan_p.add_argument("path", nargs="?", default=".", help="Project path (default: .)")
    scan_p.add_argument("--format", choices=["terminal", "json", "html", "sarif"],
                        default="terminal", help="Output format")
    scan_p.add_argument("-o", "--output", help="Output file (default: stdout)")
    scan_p.add_argument("--fix", action="store_true", help="Auto-fix safe vulnerabilities")
    scan_p.add_argument("--fix-level", choices=["critical", "high", "medium", "low"],
                        default="high", help="Maximum severity to auto-fix")
    scan_p.add_argument("--dry-run", action="store_true", help="Preview fixes without applying")
    scan_p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                        help="Exit with code 1 if vulnerabilities at or above this severity are found")
    scan_p.add_argument("--no-color", action="store_true", help="Disable colored output")
    scan_p.add_argument("--skip-deps", action="store_true", help="Skip dependency scanning")
    scan_p.add_argument("--skip-logic", action="store_true", help="Skip business logic scanning")
    scan_p.add_argument("--staged-only", nargs="*", help="Only scan specified files (for git hooks)")

    # --- fix ---
    fix_p = subparsers.add_parser("fix", help="Apply auto-fixes to existing scan issues")
    fix_p.add_argument("path", nargs="?", default=".", help="Project path")
    fix_p.add_argument("--dry-run", action="store_true", help="Preview without applying")
    fix_p.add_argument("--no-backup", action="store_true", help="Skip backup creation")
    fix_p.add_argument("--no-color", action="store_true", help="Disable colored output")

    # --- install-hooks ---
    hook_p = subparsers.add_parser("install-hooks", help="Install git pre-commit/pre-push hooks")
    hook_p.add_argument("path", nargs="?", default=".", help="Git repo path")
    hook_p.add_argument("--hooks", nargs="+", choices=["pre-commit", "pre-push"],
                        default=["pre-commit", "pre-push"])

    # --- uninstall-hooks ---
    unhook_p = subparsers.add_parser("uninstall-hooks", help="Remove installed git hooks")
    unhook_p.add_argument("path", nargs="?", default=".")

    # --- hook-status ---
    status_p = subparsers.add_parser("hook-status", help="Check hook installation status")
    status_p.add_argument("path", nargs="?", default=".")

    return parser


def run_scan(args) -> ScanResult:
    project_path = str(Path(args.path).resolve())
    scan_id = str(uuid.uuid4())[:12]
    all_vulns = []
    files_scanned = 0
    errors = []

    start = time.time()

    # Count files
    for f in Path(project_path).rglob("*.py"):
        if not any(p in f.parts for p in {"venv", ".venv", "__pycache__", ".git", "migrations"}):
            files_scanned += 1
    for f in Path(project_path).rglob("*.html"):
        if not any(p in f.parts for p in {"venv", ".venv", "__pycache__", ".git"}):
            files_scanned += 1

    # Django scanner
    try:
        scanner = DjangoScanner(project_path)
        all_vulns.extend(scanner.scan())
    except Exception as e:
        errors.append(f"Django scanner error: {e}")

    # Business logic scanner
    if not getattr(args, "skip_logic", False):
        try:
            bl_scanner = BusinessLogicScanner(project_path)
            all_vulns.extend(bl_scanner.scan())
        except Exception as e:
            errors.append(f"Business logic scanner error: {e}")

    # Dependency scanner
    if not getattr(args, "skip_deps", False):
        try:
            dep_scanner = DependencyScanner(project_path)
            all_vulns.extend(dep_scanner.scan())
        except Exception as e:
            errors.append(f"Dependency scanner error: {e}")

    duration = time.time() - start

    result = ScanResult(
        scan_id=scan_id,
        project_path=project_path,
        files_scanned=files_scanned,
        vulnerabilities=all_vulns,
        scan_duration_seconds=duration,
        errors=errors,
    )

    # Apply fixes if requested
    if getattr(args, "fix", False):
        fixer = AutoFixer(
            project_path,
            dry_run=getattr(args, "dry_run", False),
            backup=True,
        )
        fixed, skipped = fixer.apply_fixes(all_vulns)
        if args.format == "terminal":
            print(fixer.generate_fix_report())

    return result


def cmd_scan(args):
    result = run_scan(args)

    # Generate report
    if args.format == "terminal":
        reporter = TerminalReporter(no_color=args.no_color)
        output = reporter.report(result)
    elif args.format == "json":
        reporter = JSONReporter()
        output = reporter.report(result)
    elif args.format == "html":
        reporter = HTMLReporter()
        output = reporter.report(result)
    elif args.format == "sarif":
        reporter = SARIFReporter()
        output = reporter.report(result)
    else:
        output = ""

    # Write output
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if args.format == "terminal":
            print(f"\n📄 Report saved to: {args.output}")
    else:
        print(output)

    # Exit code based on --fail-on
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        sev_levels = list(SEVERITY_ORDER.values())
        threshold_idx = sev_levels.index(threshold)
        for vuln in result.vulnerabilities:
            vuln_idx = sev_levels.index(vuln.severity)
            if vuln_idx <= threshold_idx and not (vuln.fix and vuln.fix.applied):
                sys.exit(1)

    sys.exit(0)


def cmd_fix(args):
    """Run scan then apply fixes."""
    args.fix = True
    args.skip_deps = False
    args.skip_logic = False
    args.fail_on = None
    args.format = "terminal"
    args.output = None
    cmd_scan(args)


def cmd_install_hooks(args):
    path = str(Path(args.path).resolve())
    installer = HookInstaller(path)
    results = installer.install(args.hooks)

    print("🛡️  DjangoSentinel Hook Installer")
    print("=" * 45)
    for hook, result in results.items():
        if isinstance(result, dict):
            if result.get("success"):
                print(f"✅ {hook}: installed → {result['path']}")
            else:
                print(f"❌ {hook}: failed — {result.get('error')}")
    print("\n✨ Git hooks installed. Security scans will run automatically.")
    print("   To uninstall: sentinel uninstall-hooks")


def cmd_uninstall_hooks(args):
    path = str(Path(args.path).resolve())
    installer = HookInstaller(path)
    results = installer.uninstall()
    print("🛡️  DjangoSentinel: Hooks uninstalled.")
    for k, v in results.items():
        print(f"  {k}: {v}")


def cmd_hook_status(args):
    path = str(Path(args.path).resolve())
    installer = HookInstaller(path)
    status = installer.status()
    print("🛡️  DjangoSentinel Hook Status")
    print("=" * 40)
    for hook, info in status.items():
        installed = info.get("installed", False)
        icon = "✅" if installed else "❌"
        print(f"  {icon} {hook}: {'installed' if installed else 'not installed'}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "scan": cmd_scan,
        "fix": cmd_fix,
        "install-hooks": cmd_install_hooks,
        "uninstall-hooks": cmd_uninstall_hooks,
        "hook-status": cmd_hook_status,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
