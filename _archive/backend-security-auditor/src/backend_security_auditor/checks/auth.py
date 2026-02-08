"""
SECURITY DETECTION MODULE — This file contains regex patterns used to DETECT
auth misconfigurations in user codebases (weak hashing, missing MFA, unprotected routes).
These patterns are used for READ-ONLY static analysis. This code does NOT
perform any authentication operations itself.

Checks #1-3: Authentication, Token Management, Authorization.
#1 Auth done right (strong password policy + MFA where possible)
#2 Access tokens + refresh tokens (short-lived access, rotation, revoke on logout)
#3 Authorization checks everywhere (RBAC/ABAC, least privilege, no "trust the client")
"""

import re

from ..models import Finding, CheckStatus

# --- Category 1: Authentication & Password Policy ---

_WEAK_HASH_PATTERNS = [
    (re.compile(r"\bhashlib\.md5\s*\("), "MD5"),
    (re.compile(r"\bhashlib\.sha1\s*\("), "SHA1"),
    (re.compile(r"\bMD5\s*\("), "MD5"),
    (re.compile(r"\bSHA1\s*\("), "SHA1"),
    (re.compile(r"\bcrypto\.createHash\s*\(\s*['\"]md5['\"]\s*\)"), "MD5"),
    (re.compile(r"\bcrypto\.createHash\s*\(\s*['\"]sha1['\"]\s*\)"), "SHA1"),
]

# Positive signals: strong hashing
_STRONG_HASH_RE = re.compile(
    r"\b(?:bcrypt|argon2|scrypt|pbkdf2|passlib)\b", re.IGNORECASE
)

_MFA_RE = re.compile(
    r"\b(?:mfa|two_factor|2fa|totp|otp|pyotp|speakeasy|authenticator)\b", re.IGNORECASE
)

# Password length/complexity validation
_PASSWORD_VALIDATION_RE = re.compile(
    r"(?:password|passwd|pwd).*(?:len|length|min|max|\.\s*match|regex|pattern|validator)",
    re.IGNORECASE,
)


# --- Category 2: Token Management ---

# JWT without expiry
_JWT_ENCODE_RE = re.compile(r"jwt\.(?:encode|sign)\s*\(")
_JWT_EXP_RE = re.compile(r"['\"]exp['\"]|expiresIn|expires_in|expires_delta|timedelta")

# Very long token expiry (>24h for access tokens)
_LONG_EXPIRY_RE = re.compile(
    r"(?:expires[_\s]?in|expiresIn)\s*[:=]\s*['\"]?\s*(\d+)\s*[dD]"
)
_LONG_EXPIRY_SECONDS_RE = re.compile(
    r"(?:expires[_\s]?in|expiresIn)\s*[:=]\s*(\d{6,})"  # >100000 seconds ~= >27 hours
)

# Refresh token patterns (positive signals)
_REFRESH_TOKEN_RE = re.compile(r"\brefresh[_\s]?token\b", re.IGNORECASE)
_TOKEN_REVOKE_RE = re.compile(r"\b(?:revoke|invalidate|blacklist)[_\s]?token\b", re.IGNORECASE)


# --- Category 3: Authorization ---

# FastAPI routes without Depends()
_FASTAPI_ROUTE_RE = re.compile(
    r"@(?:app|router)\.\s*(?:get|post|put|patch|delete)\s*\("
)
_FASTAPI_DEPENDS_RE = re.compile(r"Depends\s*\(")

# Express routes without auth middleware
_EXPRESS_ROUTE_RE = re.compile(
    r"(?:app|router)\.\s*(?:get|post|put|patch|delete)\s*\(\s*['\"]"
)

# RBAC/permission patterns (positive signals)
_RBAC_RE = re.compile(
    r"\b(?:rbac|abac|permission|role|authorize|has_role|has_permission|"
    r"check_permission|@requires_auth|@login_required|isAdmin|isAuthenticated|"
    r"requireAuth|ensureAuthenticated)\b",
    re.IGNORECASE,
)

# Skip patterns: health, public, auth endpoints
_SKIP_ROUTE_RE = re.compile(
    r"['\"]\/(?:health|ping|status|public|auth|login|register|signup|"
    r"callback|webhook|\.well-known|favicon|robots|sitemap)['\"/]",
    re.IGNORECASE,
)

# Router-level auth injection: APIRouter(dependencies=[Depends(...)]) or include_router(dependencies=[...])
_ROUTER_LEVEL_AUTH_RE = re.compile(
    r"(?:APIRouter|include_router)\s*\([^)]*dependencies\s*=\s*\[",
)

# App-level middleware auth (middleware that handles auth for all routes)
_APP_LEVEL_AUTH_RE = re.compile(
    r"\b(?:add_middleware|middleware|@app\.middleware|"
    r"AuthenticationMiddleware|auth_middleware|verify_token)\b",
    re.IGNORECASE,
)

# Delegated auth (Clerk, Auth0, Firebase Auth, Supabase Auth, etc.)
_DELEGATED_AUTH_RE = re.compile(
    r"\b(?:clerk|auth0|firebase[_\-\s]?auth|supabase[_\-\s]?auth|"
    r"cognito|okta|keycloak)\b",
    re.IGNORECASE,
)

# Files that are clearly meant to be public
_PUBLIC_FILE_RE = re.compile(r"(?:public|webhook|health|open)", re.IGNORECASE)


def run_checks(files: list[dict], project_type: str = "unknown") -> list[Finding]:
    """Run authentication, token, and authorization checks."""
    findings = []

    has_strong_hash = False
    has_mfa = False
    has_password_validation = False
    has_jwt = False
    has_jwt_expiry = False
    has_refresh_token = False
    has_token_revocation = False
    has_rbac = False
    unprotected_routes = []
    source_files = [f for f in files if f["extension"] in (".py", ".js", ".ts") and not f["is_test"]]

    for f in source_files:
        content = f["content"]
        lines = content.split("\n")

        # Track positive signals
        if _STRONG_HASH_RE.search(content):
            has_strong_hash = True
        if _MFA_RE.search(content):
            has_mfa = True
        if _PASSWORD_VALIDATION_RE.search(content):
            has_password_validation = True
        if _REFRESH_TOKEN_RE.search(content):
            has_refresh_token = True
        if _TOKEN_REVOKE_RE.search(content):
            has_token_revocation = True
        if _RBAC_RE.search(content):
            has_rbac = True

        for i, line in enumerate(lines, 1):
            # Check for weak hashing
            for pattern, algo in _WEAK_HASH_PATTERNS:
                if pattern.search(line):
                    # Check if this is password-related context
                    context = "\n".join(lines[max(0, i - 3):i + 2]).lower()
                    if any(w in context for w in ("password", "passwd", "pwd", "credential", "secret")):
                        findings.append(Finding(
                            category="authentication",
                            category_id=1,
                            check="weak_password_hash",
                            status=CheckStatus.FAIL,
                            severity="critical",
                            message=f"Using {algo} for password hashing — easily cracked",
                            file=f["relative_path"],
                            line=i,
                            snippet=line.strip()[:120],
                            fix=f"Replace {algo} with bcrypt or argon2",
                        ))

            # Check JWT without expiry
            if _JWT_ENCODE_RE.search(line):
                has_jwt = True
                # Look in surrounding context for expiry
                context = "\n".join(lines[max(0, i - 5):i + 5])
                if _JWT_EXP_RE.search(context):
                    has_jwt_expiry = True

            # Check for very long token expiry
            long_match = _LONG_EXPIRY_RE.search(line)
            if long_match:
                days = int(long_match.group(1))
                if days > 1:
                    findings.append(Finding(
                        category="token_management",
                        category_id=2,
                        check="long_token_expiry",
                        status=CheckStatus.WARN,
                        severity="medium",
                        message=f"Token expiry set to {days} days — access tokens should be short-lived (15-60 min)",
                        file=f["relative_path"],
                        line=i,
                        snippet=line.strip()[:120],
                        fix="Use short-lived access tokens (15-60 min) with refresh token rotation",
                    ))

            long_sec_match = _LONG_EXPIRY_SECONDS_RE.search(line)
            if long_sec_match:
                seconds = int(long_sec_match.group(1))
                if seconds > 86400:
                    findings.append(Finding(
                        category="token_management",
                        category_id=2,
                        check="long_token_expiry",
                        status=CheckStatus.WARN,
                        severity="medium",
                        message=f"Token expiry set to {seconds}s ({seconds // 3600}h) — access tokens should be short-lived",
                        file=f["relative_path"],
                        line=i,
                        snippet=line.strip()[:120],
                        fix="Use short-lived access tokens (15-60 min) with refresh token rotation",
                    ))

            # Check for unprotected routes (FastAPI)
            if _FASTAPI_ROUTE_RE.search(line) and not _SKIP_ROUTE_RE.search(line):
                # Skip if file has router-level auth or is a public-facing file
                if _ROUTER_LEVEL_AUTH_RE.search(content):
                    continue
                if _PUBLIC_FILE_RE.search(f["name"]):
                    continue
                # Look for Depends() in the function signature (next few lines)
                func_context = "\n".join(lines[i - 1:min(len(lines), i + 5)])
                if not _FASTAPI_DEPENDS_RE.search(func_context):
                    unprotected_routes.append((f["relative_path"], i, line.strip()[:120]))

    # Emit summary findings for missing positive signals

    # Check if auth is delegated to a third-party provider
    has_delegated_auth = any(
        _DELEGATED_AUTH_RE.search(f["content"]) for f in source_files
    )

    if source_files and not has_strong_hash and not has_delegated_auth:
        # Only flag if there's actual password handling code (not just mentions in comments/strings)
        _PASSWORD_HANDLING_RE = re.compile(
            r"(?:password|passwd|pwd)\s*[:=]|"
            r"set_password|check_password|verify_password|hash_password|"
            r"request\.(?:form|json|body)\[?['\"]password",
            re.IGNORECASE,
        )
        has_password_code = any(
            _PASSWORD_HANDLING_RE.search(f["content"])
            for f in source_files
        )
        if has_password_code:
            findings.append(Finding(
                category="authentication",
                category_id=1,
                check="no_strong_hash",
                status=CheckStatus.WARN,
                severity="high",
                message="No bcrypt/argon2/scrypt usage detected — ensure passwords are hashed with a strong algorithm",
                fix="Use bcrypt.hashpw() or argon2.hash() for password storage",
            ))

    if not has_mfa and not has_delegated_auth:
        # Require actual auth endpoints/functions, not just words like "login" in any context
        _AUTH_ENDPOINT_RE = re.compile(
            r"(?:\/login|\/signup|\/register|\/auth\b|"
            r"def\s+(?:login|authenticate|signup)|"
            r"async\s+(?:login|authenticate|signup)|"
            r"post.*['\"].*(?:\/login|\/auth|\/register))",
            re.IGNORECASE,
        )
        has_auth_system = any(
            _AUTH_ENDPOINT_RE.search(f["content"])
            for f in source_files
        )
        if has_auth_system:
            findings.append(Finding(
                category="authentication",
                category_id=1,
                check="no_mfa",
                status=CheckStatus.WARN,
                severity="medium",
                message="No MFA/2FA implementation detected — consider adding multi-factor authentication",
                fix="Add TOTP-based MFA using pyotp (Python) or speakeasy (Node.js)",
            ))

    if has_jwt and not has_jwt_expiry:
        findings.append(Finding(
            category="token_management",
            category_id=2,
            check="jwt_no_expiry",
            status=CheckStatus.FAIL,
            severity="high",
            message="JWT tokens created without expiry — tokens live forever if not expired",
            fix="Always set 'exp' claim on JWTs. Access tokens: 15-60 min, refresh tokens: 7-30 days",
        ))

    if has_jwt and not has_refresh_token:
        findings.append(Finding(
            category="token_management",
            category_id=2,
            check="no_refresh_token",
            status=CheckStatus.WARN,
            severity="medium",
            message="No refresh token pattern detected — users may need to re-authenticate frequently or tokens are too long-lived",
            fix="Implement refresh token rotation: short-lived access tokens + longer-lived refresh tokens",
        ))

    if has_jwt and not has_token_revocation:
        findings.append(Finding(
            category="token_management",
            category_id=2,
            check="no_token_revocation",
            status=CheckStatus.WARN,
            severity="medium",
            message="No token revocation/blacklisting detected — compromised tokens cannot be invalidated",
            fix="Implement a token blacklist or use short-lived tokens with a revocable refresh token",
        ))

    # Check if auth is handled at app/middleware level (reduces severity of per-route findings)
    has_app_level_auth = any(
        _APP_LEVEL_AUTH_RE.search(f["content"]) for f in source_files
    )

    if unprotected_routes:
        if has_app_level_auth or has_delegated_auth:
            # Auth exists at app level — just note the count, don't flag individual routes
            findings.append(Finding(
                category="authorization",
                category_id=3,
                check="unprotected_route",
                status=CheckStatus.WARN,
                severity="low",
                message=f"{len(unprotected_routes)} routes without per-route auth dependencies (app-level auth detected — verify coverage)",
            ))
        else:
            # No app-level auth detected — flag top 3 routes
            for path, line, snippet in unprotected_routes[:3]:
                findings.append(Finding(
                    category="authorization",
                    category_id=3,
                    check="unprotected_route",
                    status=CheckStatus.WARN,
                    severity="high",
                    message="Route handler without auth dependency — verify this endpoint should be public",
                    file=path,
                    line=line,
                    snippet=snippet,
                    fix="Add authentication dependency: Depends(get_current_user)",
                ))

            if len(unprotected_routes) > 3:
                findings.append(Finding(
                    category="authorization",
                    category_id=3,
                    check="unprotected_route",
                    status=CheckStatus.WARN,
                    severity="high",
                    message=f"...and {len(unprotected_routes) - 3} more routes without explicit auth dependencies",
                ))

    if not has_rbac and source_files:
        has_auth_system = any(
            re.search(r"\b(?:login|auth|user|session)\b", f["content"], re.IGNORECASE)
            for f in source_files
        )
        if has_auth_system:
            findings.append(Finding(
                category="authorization",
                category_id=3,
                check="no_rbac",
                status=CheckStatus.WARN,
                severity="medium",
                message="No RBAC/ABAC pattern detected — all authenticated users may have equal access",
                fix="Implement role-based access control (RBAC) with least-privilege defaults",
            ))

    return findings
