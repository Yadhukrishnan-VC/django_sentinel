"""
Shared path helpers.

Single source of truth for which directories every scanner skips, and a
project-relative exclusion check. Matching is done on the path *relative to
the project root*, so a project that happens to live under a folder called
``env`` or ``migrations`` is still scanned.
"""

from pathlib import Path
from typing import Union

# Directories that never contain first-party source code worth scanning.
EXCLUDED_DIRS = frozenset({
    # virtual environments and dependency folders
    "venv", ".venv", "env", ".env", "node_modules", "site-packages",
    # VCS and tool caches
    ".git", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    # Django migrations (generated code)
    "migrations",
    # DjangoSentinel's own working folders (backups of fixed files, scan cache)
    ".sentinel_backups", ".sentinel_cache",
})


def is_excluded(path: Union[str, Path], root: Union[str, Path]) -> bool:
    """Return True if ``path`` lies inside an excluded directory below ``root``."""
    path = Path(path)
    try:
        parts = path.relative_to(Path(root)).parts
    except ValueError:
        parts = path.parts  # path is not under root: fall back to all parts
    return any(part in EXCLUDED_DIRS for part in parts[:-1])
