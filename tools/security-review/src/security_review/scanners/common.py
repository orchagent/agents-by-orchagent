"""Shared utilities for security pattern scanners."""

import os
from pathlib import Path
from typing import Generator


# Union of all directories to skip across all scanners
DEFAULT_SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules",
    ".git",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    "vendor",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "env",
})


def walk_repo(
    repo_path: str | Path,
    extra_skip_dirs: set[str] | None = None,
) -> Generator[tuple[Path, list[str]], None, None]:
    """Walk a repository tree, skipping known non-project directories.

    Yields (root_path, file_names) tuples, filtering out directories that should
    be skipped during scanning.

    Args:
        repo_path: Root path of the repository to walk.
        extra_skip_dirs: Additional directory names to skip (merged with DEFAULT_SKIP_DIRS).
    """
    repo_path = Path(repo_path)

    if not repo_path.exists() or not repo_path.is_dir():
        return

    skip = DEFAULT_SKIP_DIRS | extra_skip_dirs if extra_skip_dirs else DEFAULT_SKIP_DIRS

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip]
        yield Path(root), files
