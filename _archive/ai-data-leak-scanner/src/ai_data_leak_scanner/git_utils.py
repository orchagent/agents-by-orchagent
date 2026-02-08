"""Git utilities for cloning repositories."""

import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from git import Repo


def clone_repo(repo_url: str) -> Path:
    """Clone a git repository to a temporary directory (shallow clone).

    Args:
        repo_url: URL of the repository to clone.

    Returns:
        Path to the cloned repository.
    """
    temp_dir = tempfile.mkdtemp(prefix="ai_data_leak_scanner_")
    temp_path = Path(temp_dir)

    Repo.clone_from(repo_url, temp_path, depth=1)
    return temp_path


def cleanup_repo(repo_path: Path) -> None:
    """Remove a cloned repository directory.

    Args:
        repo_path: Path to the repository to remove.
    """
    if repo_path.exists():
        shutil.rmtree(repo_path, ignore_errors=True)


@contextmanager
def cloned_repo(repo_url: str) -> Generator[Path, None, None]:
    """Context manager for cloning and auto-cleanup of a repository.

    Args:
        repo_url: URL of the repository to clone.

    Yields:
        Path to the cloned repository.
    """
    repo_path = clone_repo(repo_url)
    try:
        yield repo_path
    finally:
        cleanup_repo(repo_path)
