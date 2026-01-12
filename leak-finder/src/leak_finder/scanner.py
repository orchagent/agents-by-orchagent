"""File and directory scanning for secrets."""

import os
from pathlib import Path

from .models import Finding
from .patterns import SECRET_PATTERNS

# Directories to skip during scanning
SKIP_DIRS = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    ".coverage",
    "vendor",
    "target",
}

# Binary file extensions to skip
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".pyc", ".pyo", ".class", ".o",
    ".lock", ".min.js", ".min.css",
}


def redact_secret(value: str) -> str:
    """Redact a secret value, showing only first 4 and last 4 chars."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def is_binary_file(file_path: Path) -> bool:
    """Check if a file is binary based on extension or content."""
    if file_path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except (IOError, OSError):
        return True
    return False


def get_recommendation(pattern_name: str, severity: str) -> str:
    """Generate a recommendation based on the finding type."""
    recommendations = {
        "critical": "Rotate this credential immediately and remove from codebase.",
        "high": "Rotate this credential and use environment variables instead.",
        "medium": "Consider using environment variables for this value.",
        "low": "Review if this should be in the codebase.",
        "info": "Informational finding - review as needed.",
    }
    return recommendations.get(severity, "Review this finding.")


def scan_file(file_path: str | Path, base_path: str | Path | None = None) -> list[Finding]:
    """
    Scan a single file for secrets.

    Args:
        file_path: Path to the file to scan
        base_path: Base path for relative file paths in findings

    Returns:
        List of Finding objects
    """
    file_path = Path(file_path)

    if not file_path.exists() or not file_path.is_file():
        return []

    if is_binary_file(file_path):
        return []

    findings = []

    # Determine relative path for display
    if base_path:
        try:
            display_path = str(file_path.relative_to(base_path))
        except ValueError:
            display_path = str(file_path)
    else:
        display_path = str(file_path)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                for pattern_name, pattern_info in SECRET_PATTERNS.items():
                    matches = pattern_info["regex"].finditer(line)
                    for match in matches:
                        # Get the matched value (use group 1 if it exists, else group 0)
                        try:
                            secret_value = match.group(1) if match.lastindex else match.group(0)
                        except IndexError:
                            secret_value = match.group(0)

                        finding = Finding(
                            type=pattern_name,
                            severity=pattern_info["severity"],
                            file=display_path,
                            line=line_num,
                            preview=redact_secret(secret_value),
                            in_history=False,
                            rotated=False,
                            recommendation=get_recommendation(pattern_name, pattern_info["severity"]),
                        )
                        findings.append(finding)
    except (IOError, OSError):
        pass

    return findings


def scan_directory(dir_path: str | Path, base_path: str | Path | None = None) -> list[Finding]:
    """
    Recursively scan a directory for secrets.

    Args:
        dir_path: Path to the directory to scan
        base_path: Base path for relative file paths in findings

    Returns:
        List of Finding objects
    """
    dir_path = Path(dir_path)

    if not dir_path.exists() or not dir_path.is_dir():
        return []

    if base_path is None:
        base_path = dir_path

    findings = []

    for root, dirs, files in os.walk(dir_path):
        # Filter out directories to skip
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for file_name in files:
            file_path = Path(root) / file_name
            file_findings = scan_file(file_path, base_path)
            findings.extend(file_findings)

    return findings
