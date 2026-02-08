"""Frontend security pattern scanner.

Detects security anti-patterns in frontend code:
- Supabase client usage in components (direct DB access from browser)
- Firebase Admin SDK imported in frontend code (exposes service account credentials)
- Client-side premium/auth gating patterns
- localStorage auth token patterns
- Price/cost calculations in frontend components
"""

import re
from pathlib import Path
from typing import NamedTuple

from ..models import PatternFinding
from .common import walk_repo


class PatternMatch(NamedTuple):
    """A matched pattern with its metadata."""

    name: str
    severity: str
    description: str
    recommendation: str
    regex: re.Pattern


# Frontend security patterns to detect
FRONTEND_PATTERNS: list[PatternMatch] = [
    # Supabase direct client usage in components
    PatternMatch(
        name="supabase_client_in_component",
        severity="high",
        description="Direct Supabase client usage in frontend component",
        recommendation="Move Supabase calls to server-side API routes or server actions",
        regex=re.compile(
            r'(?:from\s+[\'"]@supabase/supabase-js[\'"]|'
            r'createClient\s*\(|'
            r'supabase\.from\s*\(|'
            r'supabase\.auth\.|'
            r'useSupabaseClient)',
            re.IGNORECASE,
        ),
    ),
    # Firebase Admin SDK in frontend — exposes service account credentials
    PatternMatch(
        name="firebase_admin_in_frontend",
        severity="critical",
        description="Firebase Admin SDK imported in frontend code — exposes service account credentials",
        recommendation="Use Firebase Client SDK (firebase/...) in frontend; reserve firebase-admin for server-side only",
        regex=re.compile(
            r'(?:from\s+[\'"]firebase-admin[\'"/]|'
            r'require\s*\(\s*[\'"]firebase-admin[\'"]|'
            r'import\s+.*\s+from\s+[\'"]firebase-admin[\'"/])',
            re.IGNORECASE,
        ),
    ),
    # Client-side premium/auth gating
    PatternMatch(
        name="client_side_premium_check",
        severity="high",
        description="Client-side premium/subscription check that can be bypassed",
        recommendation="Move premium checks to server-side; client checks are easily bypassed",
        regex=re.compile(
            r'(?:if\s*\(\s*(?:user\.)?(?:isPremium|isSubscribed|hasPremium|premium|subscription|plan)\b|'
            r'user\?\.(?:isPremium|isSubscribed|premium|plan)\b|'
            r'(?:isPremium|isSubscribed|hasPremium)\s*(?:===|==|!==|!=)\s*(?:true|false))',
            re.IGNORECASE,
        ),
    ),
    PatternMatch(
        name="client_side_admin_check",
        severity="high",
        description="Client-side admin/role check that can be bypassed",
        recommendation="Move admin/role checks to server-side; client checks are easily bypassed",
        regex=re.compile(
            r'(?:if\s*\(\s*(?:user\.)?(?:isAdmin|role|isOwner|hasRole)\b|'
            r'user\?\.(?:isAdmin|role|isOwner)\s*(?:===|==|!==|!=)|'
            r'(?:isAdmin|isOwner)\s*(?:===|==)\s*true)',
            re.IGNORECASE,
        ),
    ),
    # localStorage auth/premium patterns
    PatternMatch(
        name="localstorage_premium_flag",
        severity="critical",
        description="Premium/auth flag stored in localStorage - trivially bypassable",
        recommendation="Never store feature flags in localStorage; use server-side validation",
        regex=re.compile(
            r'localStorage\.(?:get|set)Item\s*\(\s*[\'"](?:premium|isPremium|isSubscribed|auth|token|subscription|plan)[\'"]',
            re.IGNORECASE,
        ),
    ),
    PatternMatch(
        name="localstorage_auth_token",
        severity="high",
        description="Auth token in localStorage - vulnerable to XSS attacks",
        recommendation="Use httpOnly cookies for auth tokens instead of localStorage",
        regex=re.compile(
            r'localStorage\.(?:get|set)Item\s*\(\s*[\'"](?:accessToken|authToken|jwt|bearer|id_token|refresh_token)[\'"]',
            re.IGNORECASE,
        ),
    ),
    # Price/cost calculations in frontend
    PatternMatch(
        name="client_side_price_calculation",
        severity="medium",
        description="Price/cost calculation in frontend - can be tampered with",
        recommendation="Calculate prices server-side and pass to payment provider",
        regex=re.compile(
            r'(?:(?:price|cost|total|amount|subtotal)\s*[+\-*/=]\s*|'
            r'(?:calculatePrice|calculateTotal|calculateCost|getPrice)\s*\(|'
            r'\*\s*(?:quantity|qty|count)\s*)',
            re.IGNORECASE,
        ),
    ),
    PatternMatch(
        name="stripe_amount_in_frontend",
        severity="high",
        description="Stripe payment amount set in frontend - can be tampered with",
        recommendation="Set payment amounts server-side only; never trust client-provided amounts",
        regex=re.compile(
            r'(?:amount\s*:\s*(?:price|total|cost|\d+)|'
            r'stripe\.(?:paymentIntents|charges)\.create.*amount)',
            re.IGNORECASE,
        ),
    ),
]

# File extensions to scan for frontend patterns
FRONTEND_EXTENSIONS = {".tsx", ".jsx", ".ts", ".js", ".vue", ".svelte"}


def _is_frontend_file(file_path: Path) -> bool:
    """Check if a file should be scanned for frontend patterns."""
    # Check extension
    if file_path.suffix.lower() not in FRONTEND_EXTENSIONS:
        return False

    # Check path components for frontend indicators
    path_str = str(file_path).lower()

    # Skip obvious backend files
    backend_indicators = [
        "/api/",
        "/server/",
        "/backend/",
        "/lib/server",
        "/app/api/",
        "server.ts",
        "server.js",
    ]
    for indicator in backend_indicators:
        if indicator in path_str:
            return False

    # Include if in frontend-like paths
    frontend_indicators = [
        "/components/",
        "/pages/",
        "/app/",
        "/src/",
        "/views/",
        "/screens/",
        "/features/",
        "/hooks/",
        "/contexts/",
    ]
    for indicator in frontend_indicators:
        if indicator in path_str:
            return True

    # Default: scan if it's a .tsx/.jsx file (likely React component)
    return file_path.suffix.lower() in {".tsx", ".jsx"}


def scan_file(file_path: Path, base_path: Path) -> list[PatternFinding]:
    """Scan a single file for frontend security patterns."""
    if not _is_frontend_file(file_path):
        return []

    findings = []

    # Get display path
    try:
        display_path = str(file_path.relative_to(base_path))
    except ValueError:
        display_path = str(file_path)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                for pattern in FRONTEND_PATTERNS:
                    if pattern.regex.search(line):
                        # Get a snippet (trim whitespace, limit length)
                        snippet = line.strip()[:100]
                        if len(line.strip()) > 100:
                            snippet += "..."

                        findings.append(
                            PatternFinding(
                                category="frontend_security",
                                pattern=pattern.name,
                                severity=pattern.severity,
                                file=display_path,
                                line=line_num,
                                snippet=snippet,
                                recommendation=pattern.recommendation,
                            )
                        )
    except (IOError, OSError):
        pass

    return findings


def scan_frontend_patterns(
    repo_path: str | Path,
    exclude: list[str] | None = None,
) -> list[PatternFinding]:
    """
    Scan a repository for frontend security patterns.

    Args:
        repo_path: Path to the repository root
        exclude: Additional directory names to skip

    Returns:
        List of PatternFinding objects for detected issues
    """
    repo_path = Path(repo_path)
    extra_skip = set(exclude) if exclude else None

    findings = []

    for root_path, file_names in walk_repo(repo_path, extra_skip_dirs=extra_skip):
        for file_name in file_names:
            file_path = root_path / file_name
            file_findings = scan_file(file_path, repo_path)
            findings.extend(file_findings)

    return findings
