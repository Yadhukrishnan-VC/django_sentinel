"""
GitHub Pull Request Integration — DjangoSentinel
=================================================
Handles:
1. Posting PR review comments (summary + inline annotations)
2. Creating GitHub Check Run status (pass/fail)
3. Generating SARIF for GitHub Code Scanning upload
4. Reading changed files from a PR diff for targeted scanning

Environment variables:
GITHUB_TOKEN      - GitHub PAT or Actions GITHUB_TOKEN
GITHUB_REPOSITORY - owner/repo (auto-set in GitHub Actions)
GITHUB_SHA        - commit SHA (auto-set in GitHub Actions)
GITHUB_REF        - refs/pull/N/merge (auto-set in GitHub Actions)
"""

import json
import os
import re
import urllib.request
import urllib.error
from typing import Optional, List

from djangosentinel.models import ScanResult, Severity


GITHUB_API = "https://api.github.com"


def _gh_request(
    method: str,
    path: str,
    token: str,
    body: Optional[dict] = None,
    timeout: int = 15,
) -> Optional[dict]:
    """Make a GitHub API request, return parsed JSON or None."""
    url = f"{GITHUB_API}{path}"
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "DjangoSentinel/1.0.0",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="ignore")
        print(f"[DjangoSentinel] GitHub API {method} {path} → {e.code}: {body_text[:200]}")
        return None
    except Exception as e:
        print(f"[DjangoSentinel] GitHub API error: {e}")
        return None


class GitHubPRIntegration:
    """
    Full GitHub PR integration. Detects environment automatically when
    running inside GitHub Actions.
    """

    SEVERITY_ICONS = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
    }

    def __init__(
        self,
        token: Optional[str] = None,
        repo: Optional[str] = None,
        pr_number: Optional[int] = None,
        commit_sha: Optional[str] = None,
    ):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.repo = repo or os.environ.get("GITHUB_REPOSITORY", "")
        self.commit_sha = commit_sha or os.environ.get("GITHUB_SHA", "")

        # Auto-detect PR number from GITHUB_REF (refs/pull/N/merge)
        if pr_number is not None:
            self.pr_number = pr_number
        else:
            ref = os.environ.get("GITHUB_REF", "")
            match = re.search(r"refs/pull/(\d+)/", ref)
            self.pr_number = int(match.group(1)) if match else 0

        self.available = bool(self.token and self.repo)

    def get_pr_changed_files(self) -> List[str]:
        """
        Fetch the list of files changed in the current PR from GitHub API.
        Useful for targeted scanning of only changed files.
        """
        if not self.available or not self.pr_number:
            return []

        data = _gh_request(
            "GET",
            f"/repos/{self.repo}/pulls/{self.pr_number}/files",
            self.token,
        )
        if not data or not isinstance(data, list):
            return []

        return [
            f["filename"]
            for f in data
            if f.get("status") != "removed"
            and f.get("filename", "").endswith((".py", ".html", ".txt", ".toml", ".cfg"))
        ]

    def post_summary_comment(
        self,
        result: ScanResult,
        summarizer=None,
        pr_title: str = "",
    ) -> bool:
        """
        Post (or update) a summary security review comment on the PR.
        If a previous DjangoSentinel comment exists, it is updated in-place.
        """
        if not self.available or not self.pr_number:
            return False

        # Generate comment text
        if summarizer and hasattr(summarizer, "generate_pr_comment"):
            changed_files = self.get_pr_changed_files()
            comment_body = summarizer.generate_pr_comment(
                result, pr_title=pr_title, changed_files=changed_files
            )
        else:
            comment_body = self._default_comment(result)

        # Check for existing comment to update
        existing_id = self._find_existing_comment()
        if existing_id:
            resp = _gh_request(
                "PATCH",
                f"/repos/{self.repo}/issues/comments/{existing_id}",
                self.token,
                {"body": comment_body},
            )
            return resp is not None
        else:
            resp = _gh_request(
                "POST",
                f"/repos/{self.repo}/issues/{self.pr_number}/comments",
                self.token,
                {"body": comment_body},
            )
            return resp is not None

    def post_inline_review(self, result: ScanResult) -> int:
        """
        Submit a GitHub Pull Request Review with inline annotations
        on the exact lines containing vulnerabilities.

        Returns the number of inline comments successfully submitted.
        """
        if not self.available or not self.pr_number or not self.commit_sha:
            return 0

        changed_files = set(self.get_pr_changed_files())
        inline_comments = []

        for v in result.vulnerabilities:
            if v.fix and v.fix.applied:
                continue
            if changed_files and v.location.file_path not in changed_files:
                continue

            icon = self.SEVERITY_ICONS.get(v.severity, "⚪")
            body = (
                f"{icon} **{v.severity.value}: {v.title}**\n\n"
                f"{v.description}"
            )
            if v.fix and v.fix.explanation:
                body += f"\n\n**💊 Fix:** {v.fix.explanation}"
            if v.fix and v.fix.fixed_code and not v.fix.fixed_code.startswith("#"):
                body += f"\n\n```python\n{v.fix.fixed_code[:400]}\n```"
            if v.cwe_id:
                body += f"\n\n*{v.cwe_id} · {v.owasp_ref}*"

            inline_comments.append({
                "path": v.location.file_path,
                "line": v.location.line_number,
                "side": "RIGHT",
                "body": body,
            })

        if not inline_comments:
            return 0

        s = result.summary()
        event = (
            "REQUEST_CHANGES"
            if s["by_severity"]["critical"] > 0
            else "COMMENT"
        )

        resp = _gh_request(
            "POST",
            f"/repos/{self.repo}/pulls/{self.pr_number}/reviews",
            self.token,
            {
                "commit_id": self.commit_sha,
                "body": (
                    f"🛡️ DjangoSentinel found {len(result.vulnerabilities)} "
                    f"security issue(s). See inline comments for details."
                ),
                "event": event,
                "comments": inline_comments[:50],  # GitHub cap
            },
        )
        return len(inline_comments) if resp else 0

    def create_check_run(
        self,
        result: ScanResult,
        check_name: str = "DjangoSentinel Security Scan",
    ) -> bool:
        """
        Create a GitHub Check Run that shows pass/fail status on the PR
        commit, similar to a CI check.
        """
        if not self.available or not self.commit_sha:
            return False

        s = result.summary()
        total = s["total_vulnerabilities"]
        critical = s["by_severity"]["critical"]
        high = s["by_severity"]["high"]

        conclusion = "success"
        if critical > 0:
            conclusion = "failure"
        elif high > 0:
            conclusion = "action_required"

        title = (
            "✅ No vulnerabilities found"
            if total == 0
            else f"Found {total} issues (Critical: {critical}, High: {high})"
        )

        summary_lines = [
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {critical} |",
            f"| 🟠 High | {high} |",
            f"| 🟡 Medium | {s['by_severity']['medium']} |",
            f"| 🔵 Low | {s['by_severity']['low']} |",
            f"| ✅ Auto-Fixed | {s['fixed']} |",
        ]

        annotations = []
        for v in result.vulnerabilities[:50]:  # GitHub cap: 50 annotations
            annotations.append({
                "path": v.location.file_path,
                "start_line": v.location.line_number,
                "end_line": v.location.end_line or v.location.line_number,
                "annotation_level": {
                    Severity.CRITICAL: "failure",
                    Severity.HIGH: "failure",
                    Severity.MEDIUM: "warning",
                    Severity.LOW: "notice",
                }.get(v.severity, "notice"),
                "title": v.title,
                "message": v.description[:65535],
                "raw_details": (
                    f"CWE: {v.cwe_id}\nOWASP: {v.owasp_ref}\n"
                    f"Fix: {v.fix.explanation if v.fix else 'No fix available'}"
                ),
            })

        resp = _gh_request(
            "POST",
            f"/repos/{self.repo}/check-runs",
            self.token,
            {
                "name": check_name,
                "head_sha": self.commit_sha,
                "status": "completed",
                "conclusion": conclusion,
                "output": {
                    "title": title,
                    "summary": "\n".join(summary_lines),
                    "annotations": annotations,
                },
            },
        )
        return resp is not None

    def _find_existing_comment(self) -> Optional[int]:
        """Find an existing DjangoSentinel comment on the PR to update."""
        data = _gh_request(
            "GET",
            f"/repos/{self.repo}/issues/{self.pr_number}/comments",
            self.token,
        )
        if not data or not isinstance(data, list):
            return None

        sentinel_marker = "🛡️ DjangoSentinel Security Review"
        for comment in data:
            if sentinel_marker in comment.get("body", ""):
                return comment["id"]
        return None

    def _default_comment(self, result: ScanResult) -> str:
        """Fallback PR comment without AI summarizer."""
        s = result.summary()
        bsev = s["by_severity"]
        total = s["total_vulnerabilities"]

        if total == 0:
            status = "✅ **No vulnerabilities found.** Safe to merge."
        elif bsev["critical"] > 0:
            status = f"🔴 **BLOCKED** — {bsev['critical']} critical issue(s) must be fixed."
        elif bsev["high"] > 0:
            status = f"🟠 **Needs Work** — {bsev['high']} high-severity issue(s) found."
        else:
            status = f"🟡 **Review Suggested** — {total} issue(s) found."

        lines = [
            "## 🛡️ DjangoSentinel Security Review\n",
            status + "\n",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {bsev['critical']} |",
            f"| 🟠 High | {bsev['high']} |",
            f"| 🟡 Medium | {bsev['medium']} |",
            f"| 🔵 Low | {bsev['low']} |",
            f"| ✅ Auto-Fixed | {s['fixed']} |\n",
        ]

        for v in sorted(
            result.vulnerabilities,
            key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x.severity.value)
        )[:20]:
            icon = self.SEVERITY_ICONS.get(v.severity, "⚪")
            fixed = " ✅" if v.fix and v.fix.applied else ""
            lines.append(
                f"- {icon} **{v.title}**{fixed} — "
                f"`{v.location.file_path}:{v.location.line_number}`"
            )

        lines.append(
            f"\n---\n*DjangoSentinel v1.0.0 · "
            f"{s['files_scanned']} files · {s['duration_seconds']:.1f}s*"
        )
        return "\n".join(lines)
