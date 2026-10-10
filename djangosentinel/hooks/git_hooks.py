"""
Git Hook Installer.
Installs a pre-commit hook that runs DjangoSentinel before every git push.
Blocks commits/pushes containing CRITICAL vulnerabilities.
"""

import os
import stat
import subprocess
from pathlib import Path


PRE_COMMIT_HOOK = '''#!/usr/bin/env python3
"""
DjangoSentinel Pre-Commit Hook
Scans staged Python/HTML files for security vulnerabilities before commit.
"""

import subprocess
import sys
import os
from pathlib import Path

def get_staged_files():
    """Get list of staged Python and HTML files."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True
    )
    files = result.stdout.strip().split("\\n")
    return [f for f in files if f.endswith((".py", ".html")) and f]

def main():
    staged = get_staged_files()
    if not staged:
        sys.exit(0)  # Nothing to scan

    print("🛡️  DjangoSentinel: Running security scan on staged files...")

    # Find project root
    project_root = Path(subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True
    ).stdout.strip())

    try:
        result = subprocess.run(
            [sys.executable, "-m", "djangosentinel.cli", "scan",
            str(project_root),
            "--diff",
            "--staged",
            "--format", "terminal",
            "--fail-on", "critical"],
            capture_output=False,
        )

        if result.returncode != 0:
            print("\\n🚫 DjangoSentinel: Commit BLOCKED due to CRITICAL vulnerabilities.")
            print("   Fix the issues above or use --no-verify to bypass (NOT recommended).")
            print("   Run: sentinel scan . --fix  to auto-fix safe issues\\n")
            sys.exit(1)

    except FileNotFoundError:
        # DjangoSentinel not installed, skip silently
        print("⚠️  DjangoSentinel not found. Install with: pip install -e .")
        sys.exit(0)

    print("✅ DjangoSentinel: Security scan passed.\\n")
    sys.exit(0)

if __name__ == "__main__":
    main()
'''

PRE_PUSH_HOOK = '''#!/usr/bin/env python3
"""
DjangoSentinel Pre-Push Hook
Full project scan before push. Blocks on CRITICAL or HIGH vulnerabilities.
"""

import subprocess
import sys
from pathlib import Path

def main():
    print("🛡️  DjangoSentinel: Running full security scan before push...")

    project_root = Path(subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True
    ).stdout.strip())

    try:
        result = subprocess.run(
            [sys.executable, "-m", "djangosentinel.cli", "scan",
            str(project_root),
            "--diff",
            "--format", "terminal",
            "--fail-on", "high"],
            capture_output=False,
        )

        if result.returncode != 0:
            print("\\n🚫 DjangoSentinel: Push BLOCKED. Fix HIGH/CRITICAL vulnerabilities first.")
            print("   Run: sentinel scan . --fix --fix-level high\\n")
            sys.exit(1)

    except FileNotFoundError:
        print("⚠️  DjangoSentinel not found. Skipping pre-push scan.")
        sys.exit(0)

    print("✅ DjangoSentinel: Pre-push security scan passed.\\n")
    sys.exit(0)

if __name__ == "__main__":
    main()
'''


class HookInstaller:
    """Installs DjangoSentinel git hooks."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.hooks_dir = self.repo_path / ".git" / "hooks"

    def install(self, hooks: list = None) -> dict:
        """Install specified hooks. Defaults to pre-commit and pre-push."""
        if hooks is None:
            hooks = ["pre-commit", "pre-push"]

        if not self.hooks_dir.exists():
            return {"success": False, "error": "Not a git repository"}

        results = {}
        hook_scripts = {
            "pre-commit": PRE_COMMIT_HOOK,
            "pre-push": PRE_PUSH_HOOK,
        }

        for hook_name in hooks:
            hook_path = self.hooks_dir / hook_name
            script = hook_scripts.get(hook_name)

            if not script:
                results[hook_name] = {"success": False, "error": "Unknown hook type"}
                continue

            # Backup existing hook
            if hook_path.exists():
                backup = hook_path.with_suffix(".backup")
                hook_path.rename(backup)
                results[f"{hook_name}_backup"] = str(backup)

            hook_path.write_text(script, encoding="utf-8")
            hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            results[hook_name] = {"success": True, "path": str(hook_path)}

        return results

    def uninstall(self, hooks: list = None) -> dict:
        """Remove installed hooks and restore backups."""
        if hooks is None:
            hooks = ["pre-commit", "pre-push"]

        results = {}
        for hook_name in hooks:
            hook_path = self.hooks_dir / hook_name
            backup = hook_path.with_suffix(".backup")

            if hook_path.exists():
                hook_path.unlink()
                results[hook_name] = "removed"

            if backup.exists():
                backup.rename(hook_path)
                results[f"{hook_name}_restored"] = "backup restored"

        return results

    def status(self) -> dict:
        """Check installation status of hooks."""
        hooks = ["pre-commit", "pre-push"]
        status = {}
        for hook_name in hooks:
            hook_path = self.hooks_dir / hook_name
            if hook_path.exists():
                content = hook_path.read_text(encoding="utf-8", errors="ignore")
                status[hook_name] = {
                    "installed": "DjangoSentinel" in content,
                    "exists": True,
                }
            else:
                status[hook_name] = {"installed": False, "exists": False}
        return status
