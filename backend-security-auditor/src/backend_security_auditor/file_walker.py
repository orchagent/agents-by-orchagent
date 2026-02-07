"""Utility for walking repository files."""

import os
from pathlib import Path


SKIP_DIRS = {
    "node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build",
    ".next", ".nuxt", "coverage", ".coverage", "vendor", "target",
    ".pytest_cache", ".mypy_cache", "Pods", ".gradle", ".cargo",
    "DerivedData", ".bundle", ".tox", ".eggs", "bower_components",
    ".terraform", ".serverless",
}

BACKEND_EXTENSIONS = {
    ".py", ".js", ".ts", ".go", ".java", ".kt", ".rb", ".php", ".rs", ".cs",
}

CONFIG_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
}

KNOWN_FILES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore", ".gitignore", ".env", ".env.example", ".env.local",
    ".env.production", ".env.development",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock",
    "poetry.lock", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    "Gemfile", "Gemfile.lock", "pom.xml", "build.gradle",
    "nginx.conf", "apache.conf", "Caddyfile",
}

# Files that are clearly test-only
TEST_INDICATORS = {"/tests/", "/test/", "test_", "_test.", ".test.", ".spec."}


def is_test_file(relative_path: str) -> bool:
    """Check if a file path indicates it's a test file."""
    path_lower = relative_path.lower()
    return any(ind in path_lower for ind in TEST_INDICATORS)


def walk_repo(
    repo_path: str,
    extra_skip: set[str] | None = None,
) -> list[dict]:
    """
    Walk a repository and return file metadata with contents.

    Returns list of dicts with: path, relative_path, content, extension, name, is_test
    """
    skip = SKIP_DIRS | (extra_skip or set())
    all_extensions = BACKEND_EXTENSIONS | CONFIG_EXTENSIONS
    files = []

    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip]

        for name in filenames:
            filepath = Path(root) / name
            ext = filepath.suffix.lower()

            if ext not in all_extensions and name not in KNOWN_FILES:
                continue

            # Skip very large files (>500KB likely not source code)
            try:
                if filepath.stat().st_size > 500_000:
                    continue
            except OSError:
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
                relative = str(filepath.relative_to(repo_path))
                files.append({
                    "path": str(filepath),
                    "relative_path": relative,
                    "content": content,
                    "extension": ext,
                    "name": name,
                    "is_test": is_test_file(relative),
                })
            except (IOError, OSError):
                continue

    return files


def detect_project_type(files: list[dict]) -> str:
    """
    Detect project type to skip inapplicable checks.

    Returns: "api_server", "cli", "library", or "unknown"
    """
    import re

    source_files = [f for f in files if f["extension"] in (".py", ".js", ".ts")]

    # API server signals
    api_signals = 0
    for f in source_files:
        content = f["content"]
        if re.search(r"\b(?:FastAPI|Express|Flask|Django|Koa|Hapi|Gin|Echo)\b", content):
            api_signals += 3
        if re.search(r"@(?:app|router)\.\s*(?:get|post|put|patch|delete)", content):
            api_signals += 2
        if re.search(r"\.listen\s*\(|createServer|uvicorn\.run", content):
            api_signals += 2
        if re.search(r"app\.use\(|add_middleware", content):
            api_signals += 1

    # CLI signals
    cli_signals = 0
    for f in source_files:
        content = f["content"]
        if re.search(r"\b(?:argparse|commander|yargs|click|typer|Commander)\b", content):
            cli_signals += 3
        if re.search(r"sys\.argv|process\.argv", content):
            cli_signals += 2
        if re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]", content):
            cli_signals += 1

    if api_signals >= 3:
        return "api_server"
    if cli_signals >= 3:
        return "cli"
    if api_signals > 0:
        return "api_server"
    return "unknown"
