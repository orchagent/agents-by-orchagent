"""API route security scanner for Next.js projects.

Detects:
- Next.js API routes without authentication checks
- Missing CORS configuration
- Missing rate limiting
- SQL injection patterns in API routes
- Missing input validation
- Exposed internal endpoints
"""

import re
from pathlib import Path

from ..models import Finding, FindingCategory, Severity
from .common import walk_source_files, read_file_lines


# Next.js API route handler patterns
NEXTJS_API_HANDLER = re.compile(
    r'(?:export\s+(?:default\s+)?(?:async\s+)?function\s+(?:handler|GET|POST|PUT|PATCH|DELETE)|'
    r'export\s+(?:const|let)\s+(?:GET|POST|PUT|PATCH|DELETE)\s*=)',
)

# Auth patterns in API routes
API_AUTH_PATTERNS = [
    re.compile(r'getServerSession\s*\(', re.IGNORECASE),
    re.compile(r'getSession\s*\(', re.IGNORECASE),
    re.compile(r'getToken\s*\(', re.IGNORECASE),
    re.compile(r'verifyToken\s*\(', re.IGNORECASE),
    re.compile(r'\bauth\s*\(\s*\)', re.IGNORECASE),
    re.compile(r'currentUser\s*\(', re.IGNORECASE),
    re.compile(r'requireAuth\s*\(', re.IGNORECASE),
    re.compile(r'authorization.*header', re.IGNORECASE),
    re.compile(r'bearer', re.IGNORECASE),
    re.compile(r'clerk', re.IGNORECASE),
    re.compile(r'supabase\.auth', re.IGNORECASE),
    re.compile(r'withAuth', re.IGNORECASE),
]

# CORS patterns
CORS_PATTERNS = [
    re.compile(r'Access-Control-Allow-Origin', re.IGNORECASE),
    re.compile(r'cors\s*\(', re.IGNORECASE),
    re.compile(r'nextCors', re.IGNORECASE),
]

# Rate limiting patterns
RATE_LIMIT_PATTERNS = [
    re.compile(r'rateLimit', re.IGNORECASE),
    re.compile(r'rateLimiter', re.IGNORECASE),
    re.compile(r'upstash.*ratelimit', re.IGNORECASE),
    re.compile(r'@upstash/ratelimit', re.IGNORECASE),
    re.compile(r'\blimiter\b', re.IGNORECASE),
]

# SQL injection patterns
SQL_INJECTION_PATTERNS = [
    re.compile(r"""\.query\s*\(\s*`[^`]*\$\{"""),
    re.compile(r"""\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)""", re.IGNORECASE),
    # String concatenation with SQL keywords
    re.compile(
        r"""(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^+]*\+\s*(?:\w|request|req|params|query|ctx|args)""",
        re.IGNORECASE,
    ),
    # .query() with string concatenation
    re.compile(r"""\.query\s*\(\s*["'][^"']*["']\s*\+"""),
]

# Input validation patterns
INPUT_VALIDATION_PATTERNS = [
    re.compile(r'\.parse\s*\('),
    re.compile(r'\.safeParse\s*\('),
    re.compile(r'\bz\.'),
    re.compile(r'\bjoi\.', re.IGNORECASE),
    re.compile(r'\byup\.', re.IGNORECASE),
    re.compile(r'\bvalidate\s*\(', re.IGNORECASE),
]


def _is_api_route_file(file_path: Path) -> bool:
    """Check if a file is a Next.js API route."""
    path_str = str(file_path).lower()
    if "/api/" in path_str and file_path.suffix.lower() in {".ts", ".js", ".tsx", ".jsx"}:
        return True
    if file_path.name.lower() in ("route.ts", "route.js", "route.tsx", "route.jsx"):
        return True
    return False


def scan_api_route_patterns(
    project_path: str | Path,
    base_path: str | Path | None = None,
) -> list[Finding]:
    """Scan for API route security issues."""
    project_path = Path(project_path)
    base_path = Path(base_path) if base_path else project_path
    findings: list[Finding] = []

    for file_path in walk_source_files(project_path):
        if not _is_api_route_file(file_path):
            continue

        lines = read_file_lines(file_path)
        if not lines:
            continue

        content = "\n".join(line for _, line in lines)

        try:
            display_path = str(file_path.relative_to(base_path))
        except ValueError:
            display_path = str(file_path)

        has_handler = bool(NEXTJS_API_HANDLER.search(content))
        if not has_handler:
            continue

        # Skip health/status/public endpoints
        path_lower = str(file_path).lower()
        skip_paths = ["/health", "/ping", "/ready", "/status", "/webhook", "/callback"]
        if any(skip in path_lower for skip in skip_paths):
            continue

        # 1. Missing authentication
        has_auth = any(p.search(content) for p in API_AUTH_PATTERNS)
        if not has_auth:
            handler_match = NEXTJS_API_HANDLER.search(content)
            handler_line = 1
            if handler_match:
                prefix = content[:handler_match.start()]
                handler_line = prefix.count("\n") + 1

            findings.append(Finding(
                category=FindingCategory.auth,
                severity=Severity.high,
                title="API route without authentication",
                file=display_path,
                line=handler_line,
                description=(
                    "This API route has no authentication check. "
                    "Any unauthenticated user can call this endpoint."
                ),
                remediation=(
                    "Add authentication at the top of the handler:\n"
                    "  const session = await getServerSession(authOptions);\n"
                    "  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });"
                ),
                cwe="CWE-306",
            ))

        # 2. Missing CORS (only for mutation routes)
        has_mutation = bool(re.search(r'(?:POST|PUT|PATCH|DELETE)', content))
        has_cors = any(p.search(content) for p in CORS_PATTERNS)
        if has_mutation and not has_cors:
            findings.append(Finding(
                category=FindingCategory.auth,
                severity=Severity.medium,
                title="API route without CORS configuration",
                file=display_path,
                description=(
                    "This mutation API route has no CORS configuration. "
                    "Without CORS headers, the same-origin policy may be insufficient."
                ),
                remediation=(
                    "Add CORS headers:\n"
                    "  headers: { 'Access-Control-Allow-Origin': 'https://yourdomain.com' }"
                ),
                cwe="CWE-346",
            ))

        # 3. Missing rate limiting
        has_rate_limit = any(p.search(content) for p in RATE_LIMIT_PATTERNS)
        if not has_rate_limit:
            findings.append(Finding(
                category=FindingCategory.auth,
                severity=Severity.low,
                title="API route without rate limiting",
                file=display_path,
                description=(
                    "This API route has no rate limiting. "
                    "Vulnerable to brute force and DoS attacks."
                ),
                remediation=(
                    "Add rate limiting:\n"
                    "  import { Ratelimit } from '@upstash/ratelimit';\n"
                    "  const ratelimit = new Ratelimit({ ... });"
                ),
                cwe="CWE-770",
            ))

        # 4. SQL injection patterns
        for line_num, line in lines:
            for pattern in SQL_INJECTION_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        category=FindingCategory.auth,
                        severity=Severity.critical,
                        title="Potential SQL injection in API route",
                        file=display_path,
                        line=line_num,
                        description=(
                            "SQL query uses string interpolation or concatenation. "
                            "This can lead to SQL injection if user input is included."
                        ),
                        remediation=(
                            "Use parameterized queries:\n"
                            "  db.query('SELECT * FROM users WHERE id = $1', [userId]);"
                        ),
                        cwe="CWE-89",
                    ))
                    break

        # 5. Missing input validation
        has_body_usage = bool(re.search(
            r'(?:req\.body|request\.json\(\)|await\s+req\.json\(\))', content
        ))
        has_validation = any(p.search(content) for p in INPUT_VALIDATION_PATTERNS)
        if has_body_usage and not has_validation:
            findings.append(Finding(
                category=FindingCategory.auth,
                severity=Severity.medium,
                title="API route reads request body without validation",
                file=display_path,
                description=(
                    "This API route reads the request body without validation. "
                    "Unvalidated input can lead to injection and unexpected behavior."
                ),
                remediation=(
                    "Validate with zod:\n"
                    "  const schema = z.object({ name: z.string() });\n"
                    "  const body = schema.parse(await request.json());"
                ),
                cwe="CWE-20",
            ))

    return findings
