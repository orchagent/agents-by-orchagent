"""Shared utilities for AI data leak scanners."""

import os
from pathlib import Path
from typing import Generator


# Directories to skip during scanning
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
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
})

# Source file extensions to scan
SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs",
    ".java", ".go", ".rb", ".rs", ".cs", ".php",
})

# Schema/config file extensions
SCHEMA_EXTENSIONS: frozenset[str] = frozenset({
    ".sql", ".prisma", ".graphql", ".gql",
})

# All scannable extensions
ALL_EXTENSIONS: frozenset[str] = SOURCE_EXTENSIONS | SCHEMA_EXTENSIONS


def walk_source_files(
    path: str | Path,
    extensions: frozenset[str] | None = None,
    exclude_dirs: set[str] | None = None,
) -> Generator[Path, None, None]:
    """Walk directory tree yielding source files.

    Args:
        path: Root directory to walk.
        extensions: File extensions to include. Defaults to SOURCE_EXTENSIONS.
        exclude_dirs: Additional directory names to skip.

    Yields:
        Path objects for matching source files.
    """
    root = Path(path)
    if not root.exists() or not root.is_dir():
        return

    exts = extensions or SOURCE_EXTENSIONS
    skip = DEFAULT_SKIP_DIRS | exclude_dirs if exclude_dirs else DEFAULT_SKIP_DIRS

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() in exts:
                yield fpath


def read_file_lines(path: str | Path) -> list[tuple[int, str]]:
    """Read a file and return list of (line_number, line_content) tuples.

    Args:
        path: Path to the file to read.

    Returns:
        List of (line_number, line_content) tuples. Line numbers start at 1.
        Returns empty list if file cannot be read.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [(i, line) for i, line in enumerate(f, start=1)]
    except (IOError, OSError):
        return []


def get_display_path(file_path: Path, base_path: Path) -> str:
    """Get a display-friendly relative path.

    Args:
        file_path: Absolute path to the file.
        base_path: Base path to make relative to.

    Returns:
        Relative path string, or absolute path if not relative.
    """
    try:
        return str(file_path.relative_to(base_path))
    except ValueError:
        return str(file_path)


def detect_file_type(file_path: Path) -> str:
    """Detect the programming language of a file.

    Args:
        file_path: Path to the file.

    Returns:
        Language identifier string (e.g., "python", "javascript", "typescript").
    """
    ext_map = {
        ".py": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".rs": "rust",
        ".cs": "csharp",
        ".php": "php",
        ".sql": "sql",
        ".prisma": "prisma",
        ".graphql": "graphql",
        ".gql": "graphql",
    }
    return ext_map.get(file_path.suffix.lower(), "unknown")
