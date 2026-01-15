"""API security pattern scanner.

Detects security anti-patterns in API code:
- FastAPI routes without Depends() for authentication
- Express routes without auth middleware
- Missing rate limiter patterns
"""

import os
import re
from pathlib import Path
from typing import NamedTuple

from ..models import PatternFinding


class PatternMatch(NamedTuple):
    """A matched pattern with its metadata."""

    name: str
    severity: str
    description: str
    recommendation: str
    regex: re.Pattern


# FastAPI patterns for detecting missing auth
FASTAPI_ROUTE_PATTERN = re.compile(
    r'@(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*[\'"][^\'"]+[\'"]',
    re.IGNORECASE,
)

FASTAPI_DEPENDS_PATTERN = re.compile(
    r'Depends\s*\(',
    re.IGNORECASE,
)

# Express patterns for detecting missing auth
EXPRESS_ROUTE_PATTERN = re.compile(
    r'(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*[\'"][^\'"]+[\'"]',
    re.IGNORECASE,
)

EXPRESS_AUTH_MIDDLEWARE_PATTERN = re.compile(
    r'(?:requireAuth|authenticate|isAuthenticated|authMiddleware|verifyToken|checkAuth|ensureAuth)',
    re.IGNORECASE,
)

# Rate limiting patterns
RATE_LIMITER_PATTERNS = [
    re.compile(r'(?:RateLimiter|slowdown|rate.?limit)', re.IGNORECASE),
    re.compile(r'from\s+[\'"](?:slowapi|ratelimit|fastapi-limiter)[\'"]', re.IGNORECASE),
    re.compile(r'(?:require|import).*(?:express-rate-limit|rate-limiter-flexible)', re.IGNORECASE),
]

# File extensions for API files
API_EXTENSIONS = {".py", ".ts", ".js", ".mjs", ".cjs"}

# Directories to skip during scanning
SKIP_DIRS = {
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
}

# Paths that indicate API code
API_PATH_INDICATORS = [
    "/api/",
    "/routes/",
    "/routers/",
    "/endpoints/",
    "/controllers/",
    "/server/",
    "/backend/",
    "/app/api/",
]

# Paths that indicate frontend/test code (to exclude)
EXCLUDE_PATH_INDICATORS = [
    "/tests/",
    "/test/",
    "/__tests__/",
    "/spec/",
    "/components/",
    "/pages/",
    "/views/",
    "test_",
    "_test.",
    ".test.",
    ".spec.",
]


def _is_api_file(file_path: Path) -> bool:
    """Check if a file should be scanned for API patterns."""
    # Check extension
    if file_path.suffix.lower() not in API_EXTENSIONS:
        return False

    path_str = str(file_path).lower()

    # Exclude test files
    for indicator in EXCLUDE_PATH_INDICATORS:
        if indicator in path_str:
            return False

    # Include if in API-like paths
    for indicator in API_PATH_INDICATORS:
        if indicator in path_str:
            return True

    # Check for API-related filenames
    filename = file_path.name.lower()
    api_filenames = ["main.py", "app.py", "server.py", "index.ts", "index.js", "server.ts", "server.js"]
    if filename in api_filenames:
        return True

    return False


def _check_fastapi_auth(file_path: Path, content: str, lines: list[str], base_path: Path) -> list[PatternFinding]:
    """Check FastAPI routes for missing Depends() authentication."""
    findings = []

    try:
        display_path = str(file_path.relative_to(base_path))
    except ValueError:
        display_path = str(file_path)

    # Check if it's a FastAPI file
    if "fastapi" not in content.lower() and "@app." not in content and "@router." not in content:
        return []

    for line_num, line in enumerate(lines, start=1):
        # Check if line contains a route decorator
        if FASTAPI_ROUTE_PATTERN.search(line):
            # Look for Depends in the route decorator or the function signature
            # Check this line and the next few lines (function signature could span lines)
            context_start = max(0, line_num - 1)
            context_end = min(len(lines), line_num + 4)
            context = "\n".join(lines[context_start:context_end])

            if not FASTAPI_DEPENDS_PATTERN.search(context):
                # Skip common exceptions
                route_path = line.lower()
                if any(skip in route_path for skip in ["/health", "/ping", "/ready", "/docs", "/openapi", "/redoc"]):
                    continue

                snippet = line.strip()[:100]
                if len(line.strip()) > 100:
                    snippet += "..."

                findings.append(
                    PatternFinding(
                        category="api_security",
                        pattern="fastapi_missing_auth",
                        severity="high",
                        file=display_path,
                        line=line_num,
                        snippet=snippet,
                        recommendation="Add authentication using Depends() with an auth dependency",
                    )
                )

    return findings


def _check_express_auth(file_path: Path, content: str, lines: list[str], base_path: Path) -> list[PatternFinding]:
    """Check Express routes for missing auth middleware."""
    findings = []

    try:
        display_path = str(file_path.relative_to(base_path))
    except ValueError:
        display_path = str(file_path)

    # Check if it's an Express file
    if "express" not in content.lower():
        return []

    for line_num, line in enumerate(lines, start=1):
        # Check if line contains a route definition
        if EXPRESS_ROUTE_PATTERN.search(line):
            # Check if auth middleware is present in the route
            if not EXPRESS_AUTH_MIDDLEWARE_PATTERN.search(line):
                # Skip common exceptions
                route_path = line.lower()
                if any(skip in route_path for skip in ["/health", "/ping", "/ready", "/docs", "/api-docs"]):
                    continue

                snippet = line.strip()[:100]
                if len(line.strip()) > 100:
                    snippet += "..."

                findings.append(
                    PatternFinding(
                        category="api_security",
                        pattern="express_missing_auth",
                        severity="high",
                        file=display_path,
                        line=line_num,
                        snippet=snippet,
                        recommendation="Add authentication middleware to protect this route",
                    )
                )

    return findings


def _check_rate_limiting(file_path: Path, content: str, base_path: Path) -> list[PatternFinding]:
    """Check if API file has rate limiting configured."""
    findings = []

    try:
        display_path = str(file_path.relative_to(base_path))
    except ValueError:
        display_path = str(file_path)

    # Check if this is an API entry point file
    filename = file_path.name.lower()
    entry_point_names = ["main.py", "app.py", "server.py", "index.ts", "index.js", "server.ts", "server.js"]

    if filename not in entry_point_names:
        return []

    # Check if any rate limiting pattern is present
    has_rate_limiter = False
    for pattern in RATE_LIMITER_PATTERNS:
        if pattern.search(content):
            has_rate_limiter = True
            break

    if not has_rate_limiter:
        # Only report if this looks like an API server
        api_indicators = ["fastapi", "flask", "express", "app.listen", "uvicorn", "router"]
        is_api_server = any(indicator in content.lower() for indicator in api_indicators)

        if is_api_server:
            findings.append(
                PatternFinding(
                    category="api_security",
                    pattern="missing_rate_limiter",
                    severity="medium",
                    file=display_path,
                    line=1,
                    snippet="No rate limiting detected in API entry point",
                    recommendation="Add rate limiting to prevent abuse (e.g., slowapi for FastAPI, express-rate-limit for Express)",
                )
            )

    return findings


def scan_file(file_path: Path, base_path: Path) -> list[PatternFinding]:
    """Scan a single file for API security patterns."""
    if not _is_api_file(file_path):
        return []

    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.split("\n")

        # Run all API security checks
        findings.extend(_check_fastapi_auth(file_path, content, lines, base_path))
        findings.extend(_check_express_auth(file_path, content, lines, base_path))
        findings.extend(_check_rate_limiting(file_path, content, base_path))

    except (IOError, OSError):
        pass

    return findings


def scan_api_patterns(repo_path: str | Path) -> list[PatternFinding]:
    """
    Scan a repository for API security patterns.

    Args:
        repo_path: Path to the repository root

    Returns:
        List of PatternFinding objects for detected issues
    """
    repo_path = Path(repo_path)

    if not repo_path.exists() or not repo_path.is_dir():
        return []

    findings = []

    for root, dirs, files in os.walk(repo_path):
        # Filter out directories to skip
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for file_name in files:
            file_path = Path(root) / file_name
            file_findings = scan_file(file_path, repo_path)
            findings.extend(file_findings)

    return findings
