"""Shared utilities for React/Next.js security scanners."""

import os
from pathlib import Path
from typing import Generator


DEFAULT_SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules",
    ".git",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    ".turbo",
    ".vercel",
    "out",
})

SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
})


def walk_source_files(
    path: str | Path,
    extensions: frozenset[str] | set[str] | None = None,
    exclude_dirs: set[str] | None = None,
) -> Generator[Path, None, None]:
    """Walk a project tree yielding source files.

    Args:
        path: Root directory to walk.
        extensions: File extensions to include (default: SOURCE_EXTENSIONS).
        exclude_dirs: Additional directory names to skip.

    Yields:
        Path objects for matching source files.
    """
    path = Path(path)
    if not path.exists() or not path.is_dir():
        return

    exts = extensions if extensions is not None else SOURCE_EXTENSIONS
    skip = DEFAULT_SKIP_DIRS | exclude_dirs if exclude_dirs else DEFAULT_SKIP_DIRS

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip]
        for fname in files:
            if Path(fname).suffix.lower() in exts:
                yield Path(root) / fname


def read_file_lines(path: str | Path) -> list[tuple[int, str]]:
    """Read a file and return numbered lines.

    Args:
        path: Path to the file.

    Returns:
        List of (line_number, line_content) tuples (1-indexed).
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [(i, line) for i, line in enumerate(f, start=1)]
    except (IOError, OSError):
        return []


_USE_CLIENT_MARKERS = frozenset({
    '"use client"',
    "'use client'",
    '"use client";',
    "'use client';",
})

_USE_SERVER_MARKERS = frozenset({
    '"use server"',
    "'use server'",
    '"use server";',
    "'use server';",
})


def is_client_component(file_path: str | Path, content: str) -> bool:
    """Check if a file is a React Client Component.

    A file is a client component if it has the 'use client' directive.
    """
    for line in content.split("\n")[:5]:
        stripped = line.strip()
        if stripped in _USE_CLIENT_MARKERS:
            return True
        if stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
            break
    return False


def is_server_component(file_path: str | Path, content: str) -> bool:
    """Check if a file is a React Server Component.

    In App Router, default is server component (no 'use client' directive).
    """
    file_path = Path(file_path)
    path_str = str(file_path).lower()

    for line in content.split("\n")[:5]:
        stripped = line.strip()
        if stripped in _USE_SERVER_MARKERS:
            return True
        if stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
            break

    # In App Router, absence of 'use client' means server component
    app_router_indicators = ["/app/", "/src/app/"]
    is_in_app_router = any(ind in path_str for ind in app_router_indicators)

    if is_in_app_router and not is_client_component(file_path, content):
        return True

    return False
