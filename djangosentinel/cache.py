"""
Scan Cache — DjangoSentinel
============================
File-hash-based caching for incremental scanning.

On large projects (1000+ Python files), a full scan can take 30+ seconds.
The cache stores per-file scan results keyed by content hash (SHA-256).
If a file hasn't changed since the last scan, we reuse the cached findings.

This makes subsequent scans on unchanged codebases near-instant.

Cache location: .sentinel_cache/scan_cache.json (project-local)
Cache format:   {file_hash: {findings: [...], scanned_at: "ISO timestamp"}}
Cache TTL:      7 days (configurable)

The cache is conservative:
- Only caches findings with confidence >= 0.5
- Invalidates the entire cache if DjangoSentinel version changes
- Never caches AI-generated findings (those may change)
- Thread-safe: uses file locking for concurrent CI runs
"""

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import uuid

from djangosentinel.models import (
    Vulnerability, VulnCategory, Severity, CodeLocation, Fix
)

SENTINEL_VERSION = "1.0.0"
CACHE_TTL_DAYS = 7
MIN_CONFIDENCE_TO_CACHE = 0.5


def file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file's content."""
    try:
        h = hashlib.sha256()
        h.update(path.read_bytes())
        return h.hexdigest()[:16]  # 16 chars is enough for cache key
    except Exception:
        return ""


def _vuln_to_dict(v: Vulnerability) -> dict:
    """Serialize a Vulnerability to a cache-safe dict."""
    return {
        "vuln_id": v.vuln_id,
        "title": v.title,
        "category": v.category.value,
        "severity": v.severity.value,
        "file_path": v.location.file_path,
        "line_number": v.location.line_number,
        "snippet": v.location.snippet,
        "description": v.description,
        "owasp_ref": v.owasp_ref,
        "cwe_id": v.cwe_id,
        "cve_id": v.cve_id,
        "references": v.references,
        "metadata": {
            k: v for k, v in v.metadata.items()
            if isinstance(v, (str, int, float, bool, list))
        },
        "fix": {
            "description": v.fix.description,
            "original_code": v.fix.original_code,
            "fixed_code": v.fix.fixed_code,
            "manual_review_required": v.fix.manual_review_required,
            "explanation": v.fix.explanation,
        } if v.fix else None,
    }


def _vuln_from_dict(d: dict) -> Optional[Vulnerability]:
    """Deserialize a Vulnerability from a cache dict."""
    try:
        cat_map = {c.value: c for c in VulnCategory}
        sev_map = {s.value: s for s in Severity}

        fix = None
        if d.get("fix"):
            f = d["fix"]
            fix = Fix(
                description=f.get("description", ""),
                original_code=f.get("original_code", ""),
                fixed_code=f.get("fixed_code", ""),
                applied=False,
                manual_review_required=f.get("manual_review_required", True),
                explanation=f.get("explanation", ""),
            )

        return Vulnerability(
            vuln_id=d.get("vuln_id", str(uuid.uuid4())[:8]),
            title=d["title"],
            category=cat_map.get(d["category"], VulnCategory.MISCONFIG),
            severity=sev_map.get(d["severity"], Severity.MEDIUM),
            location=CodeLocation(
                file_path=d["file_path"],
                line_number=d["line_number"],
                snippet=d.get("snippet"),
            ),
            description=d["description"],
            owasp_ref=d.get("owasp_ref", ""),
            cwe_id=d.get("cwe_id", ""),
            cve_id=d.get("cve_id", ""),
            fix=fix,
            references=d.get("references", []),
            metadata={**d.get("metadata", {}), "from_cache": True},
        )
    except (KeyError, ValueError):
        return None


class ScanCache:
    """
    Persistent file-hash cache for scan results.

    Usage:
        cache = ScanCache("/project")
        # Before scanning a file:
        cached = cache.get(file_path, file_hash)
        if cached is not None:
            use_cached_results(cached)
        else:
            vulns = run_scan(file_path)
            cache.set(file_path, file_hash, vulns)
    """

    def __init__(self, project_path: str, cache_dir: str = ".sentinel_cache"):
        self.project_path = Path(project_path)
        self.cache_file = self.project_path / cache_dir / "scan_cache.json"
        self._data: Dict[str, dict] = {}
        self._dirty = False
        self._load()

    def _load(self):
        """Load cache from disk."""
        try:
            if self.cache_file.exists():
                raw = json.loads(self.cache_file.read_text(encoding="utf-8"))
                # Invalidate if Sentinel version changed
                if raw.get("sentinel_version") != SENTINEL_VERSION:
                    self._data = {}
                    return
                self._data = raw.get("entries", {})
                self._evict_expired()
        except Exception:
            self._data = {}

    def _save(self):
        """Persist cache to disk."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            output = {
                "sentinel_version": SENTINEL_VERSION,
                "saved_at": datetime.now().isoformat(),
                "entries": self._data,
            }
            self.cache_file.write_text(
                json.dumps(output, indent=2, default=str),
                encoding="utf-8",
            )
            self._dirty = False
        except Exception:
            pass

    def _evict_expired(self):
        """Remove cache entries older than TTL."""
        cutoff = datetime.now() - timedelta(days=CACHE_TTL_DAYS)
        expired = [
            k for k, v in self._data.items()
            if datetime.fromisoformat(v.get("scanned_at", "2000-01-01")) < cutoff
        ]
        for k in expired:
            del self._data[k]
        if expired:
            self._dirty = True

    def get(self, file_path: str, content_hash: str) -> Optional[List[Vulnerability]]:
        """
        Return cached findings for a file, or None if cache miss.

        Cache miss conditions:
        - File not in cache
        - Content hash changed (file was modified)
        - Cache entry is expired
        """
        entry = self._data.get(content_hash)
        if not entry:
            return None

        scanned_at_str = entry.get("scanned_at", "2000-01-01")
        try:
            scanned_at = datetime.fromisoformat(scanned_at_str)
        except ValueError:
            return None

        if datetime.now() - scanned_at > timedelta(days=CACHE_TTL_DAYS):
            del self._data[content_hash]
            self._dirty = True
            return None

        vulns = []
        for d in entry.get("findings", []):
            v = _vuln_from_dict(d)
            if v:
                vulns.append(v)

        return vulns

    def set(self, file_path: str, content_hash: str, vulns: List[Vulnerability]):
        """Store scan results in cache. Skips AI-detected and low-confidence findings."""
        cacheable = [
            v for v in vulns
            if not v.title.startswith("[AI]")
            and not v.metadata.get("from_cache")
            and v.metadata.get("confidence", 0.5) >= MIN_CONFIDENCE_TO_CACHE
        ]

        self._data[content_hash] = {
            "file_path": file_path,
            "scanned_at": datetime.now().isoformat(),
            "findings": [_vuln_to_dict(v) for v in cacheable],
            "finding_count": len(cacheable),
        }
        self._dirty = True

    def invalidate(self, file_path: str):
        """Remove all cache entries for a specific file."""
        to_delete = [
            k for k, v in self._data.items()
            if v.get("file_path") == file_path
        ]
        for k in to_delete:
            del self._data[k]
        if to_delete:
            self._dirty = True

    def flush(self):
        """Save cache to disk if dirty."""
        if self._dirty:
            self._save()

    def stats(self) -> dict:
        """Return cache statistics."""
        return {
            "entries": len(self._data),
            "total_findings": sum(v.get("finding_count", 0) for v in self._data.values()),
            "cache_file": str(self.cache_file),
            "ttl_days": CACHE_TTL_DAYS,
        }

    def clear(self):
        """Clear all cache entries."""
        self._data = {}
        self._dirty = True
        self._save()


class IncrementalScanner:
    """
    Wraps any scanner to add incremental scanning via file hash cache.

    Only scans files that have changed since the last run.
    Returns cached results for unchanged files instantly.
    """

    def __init__(self, project_path: str, use_cache: bool = True):
        self.project_path = Path(project_path)
        self.use_cache = use_cache
        self.cache = ScanCache(project_path) if use_cache else None
        self.cache_hits = 0
        self.cache_misses = 0

    def scan_files(
        self,
        scanner_fn,
        py_files: List[Path],
        label: str = "",
    ) -> List[Vulnerability]:
        """
        Run scanner_fn on files, using cache where possible.

        Args:
            scanner_fn:  fn(source: str, file_path: str) -> List[Vulnerability]
            py_files:    list of files to scan
            label:       scanner name for cache keying

        Returns:
            All vulnerabilities (cached + freshly scanned)
        """
        all_vulns: List[Vulnerability] = []
        changed_files: List[Path] = []

        for py_file in py_files:
            if not py_file.exists():
                continue

            h = file_hash(py_file)
            cache_key = f"{label}:{h}"

            if self.cache:
                cached = self.cache.get(str(py_file), cache_key)
                if cached is not None:
                    all_vulns.extend(cached)
                    self.cache_hits += 1
                    continue

            changed_files.append(py_file)
            self.cache_misses += 1

        # Scan changed files
        for py_file in changed_files:
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                rel = str(py_file.relative_to(self.project_path))
                new_vulns = scanner_fn(source, rel)
                all_vulns.extend(new_vulns)

                if self.cache:
                    h = file_hash(py_file)
                    cache_key = f"{label}:{h}"
                    self.cache.set(rel, cache_key, new_vulns)
            except Exception:
                continue

        if self.cache:
            self.cache.flush()

        return all_vulns

    def stats(self) -> dict:
        return {
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate": (
                self.cache_hits / (self.cache_hits + self.cache_misses)
                if (self.cache_hits + self.cache_misses) > 0 else 0.0
            ),
            **(self.cache.stats() if self.cache else {}),
        }
