"""
SECURITY DETECTION MODULE — This file contains regex patterns used to DETECT
infrastructure misconfigurations (missing rate limiting, hardcoded secrets, insecure TLS).
These patterns are used for READ-ONLY static analysis scanning user codebases.

Checks #6-8: Rate Limiting, Secrets Management, TLS.
#6 Rate limiting + abuse protection (per IP/user/key + anomaly detection)
#7 Secure secrets management (Vault/KMS, no secrets in env/logs/repos)
#8 TLS everywhere (mTLS internally if needed, HSTS, modern ciphers)
"""

import re

from ..models import Finding, CheckStatus


# --- Category 6: Rate Limiting ---

_RATE_LIMIT_RE = re.compile(
    r"\b(?:rate[_\-\s]?limit|rateLimit|RateLimit|throttle|Throttle|"
    r"slowapi|SlowAPI|express-rate-limit|rateLimit|"
    r"@throttle|RateLimiter|limiter|bucket4j)\b",
    re.IGNORECASE,
)


# --- Category 7: Secrets Management ---

# Hardcoded secret patterns (focused — not as broad as leak-finder)
_HARDCODED_SECRET_PATTERNS = [
    # API key assignments
    (re.compile(r"""(?:api[_\-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]""", re.IGNORECASE),
     "Hardcoded API key", "high"),
    # Password assignments (not in validation context)
    (re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]""", re.IGNORECASE),
     "Hardcoded password", "critical"),
    # Secret key assignments
    (re.compile(r"""(?:secret[_\-]?key|SECRET_KEY)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]"""),
     "Hardcoded secret key", "critical"),
    # Database URIs with credentials
    (re.compile(r"""(?:database[_\-]?url|DATABASE_URL|db_url)\s*[:=]\s*['"](?:postgres|mysql|mongodb)://[^'"]*:[^'"]*@""", re.IGNORECASE),
     "Database URI with credentials hardcoded", "critical"),
]

# Vault/KMS usage (positive signals)
_VAULT_KMS_RE = re.compile(
    r"\b(?:vault|hashicorp|aws[_\-]?kms|KMS|secret[_\-]?manager|"
    r"SecretManager|ssm|ParameterStore|doppler|infisical)\b",
    re.IGNORECASE,
)

# .env file committed check
_ENV_FILE_NAMES = {".env", ".env.local", ".env.production", ".env.development"}

# .gitignore patterns
_GITIGNORE_ENV_RE = re.compile(r"^\s*\.env", re.MULTILINE)

# False positive indicators for secrets
_SECRET_FP_INDICATORS = [
    "example", "placeholder", "changeme", "your_", "xxx", "test", "fake",
    "dummy", "sample", "todo", "fixme",
]


# --- Category 8: TLS ---

# HTTP URLs in config (not localhost)
_HTTP_URL_RE = re.compile(
    r"""['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[a-zA-Z0-9]"""
)

# HSTS header (positive signal)
_HSTS_RE = re.compile(
    r"\b(?:Strict-Transport-Security|HSTS|hsts)\b", re.IGNORECASE
)

# TLS/SSL verification disabled
_TLS_INSECURE_RE = re.compile(
    r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]|"
    r"VERIFY_SSL\s*=\s*False|ssl[_\-]?verify\s*[:=]\s*(?:false|False|0))",
    re.IGNORECASE,
)


def run_checks(files: list[dict], project_type: str = "unknown") -> list[Finding]:
    """Run rate limiting, secrets, and TLS checks."""
    findings = []
    source_files = [f for f in files if f["extension"] in (".py", ".js", ".ts") and not f["is_test"]]
    all_files = [f for f in files if not f["is_test"]]

    has_rate_limiting = False
    has_vault_kms = False
    has_hsts = False

    # Check if .gitignore protects .env (check all .gitignore files in the repo)
    gitignore_protects_env = False
    for f in files:
        if f["name"] == ".gitignore":
            if _GITIGNORE_ENV_RE.search(f["content"]):
                gitignore_protects_env = True

    # Also check if this is a subdirectory of a larger repo with its own .gitignore
    # by looking for .env.example (suggests .env management is intentional)
    has_env_example = any(f["name"] == ".env.example" for f in files)
    if has_env_example:
        gitignore_protects_env = True

    for f in source_files:
        content = f["content"]
        lines = content.split("\n")

        if _RATE_LIMIT_RE.search(content):
            has_rate_limiting = True
        if _VAULT_KMS_RE.search(content):
            has_vault_kms = True
        if _HSTS_RE.search(content):
            has_hsts = True

        for i, line in enumerate(lines, 1):
            # Hardcoded secrets
            for pattern, desc, severity in _HARDCODED_SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    matched_text = match.group(0).lower()
                    # Skip false positives
                    if any(fp in matched_text for fp in _SECRET_FP_INDICATORS):
                        continue
                    # Skip comments
                    stripped = line.strip()
                    if stripped.startswith(("#", "//", "*", "/*")):
                        continue

                    findings.append(Finding(
                        category="secrets_management",
                        category_id=7,
                        check="hardcoded_secret",
                        status=CheckStatus.FAIL,
                        severity=severity,
                        message=f"{desc} in source code",
                        file=f["relative_path"],
                        line=i,
                        snippet=stripped[:80] + "..." if len(stripped) > 80 else stripped,
                        fix="Move secrets to environment variables or a secrets manager (Vault, AWS KMS, Doppler)",
                    ))

            # HTTP URLs
            if _HTTP_URL_RE.search(line):
                stripped = line.strip()
                if not stripped.startswith(("#", "//", "*")):
                    findings.append(Finding(
                        category="tls",
                        category_id=8,
                        check="http_url",
                        status=CheckStatus.WARN,
                        severity="medium",
                        message="Non-TLS HTTP URL found — data transmitted in plaintext",
                        file=f["relative_path"],
                        line=i,
                        snippet=stripped[:120],
                        fix="Use HTTPS for all external connections",
                    ))

            # TLS verification disabled
            if _TLS_INSECURE_RE.search(line):
                findings.append(Finding(
                    category="tls",
                    category_id=8,
                    check="tls_verification_disabled",
                    status=CheckStatus.FAIL,
                    severity="high",
                    message="TLS certificate verification disabled — vulnerable to MITM attacks",
                    file=f["relative_path"],
                    line=i,
                    snippet=line.strip()[:120],
                    fix="Enable TLS verification. Only disable in development if absolutely necessary",
                ))

    # Check for .env files committed without .gitignore protection
    for f in all_files:
        if f["name"] in _ENV_FILE_NAMES and f["name"] != ".env.example":
            if not gitignore_protects_env:
                findings.append(Finding(
                    category="secrets_management",
                    category_id=7,
                    check="env_file_exposed",
                    status=CheckStatus.FAIL,
                    severity="high",
                    message=f"{f['name']} file present and .gitignore doesn't exclude .env files",
                    file=f["relative_path"],
                    fix="Add '.env*' to .gitignore and remove .env files from version control",
                ))

    # Summary findings for missing infrastructure (only for API server projects)
    is_api_server = project_type == "api_server"
    has_api_routes = is_api_server or any(
        re.search(r"@(?:app|router)\.|\.listen\(|createServer", f["content"])
        for f in source_files
    )

    if has_api_routes and not has_rate_limiting:
        findings.append(Finding(
            category="rate_limiting",
            category_id=6,
            check="no_rate_limiting",
            status=CheckStatus.FAIL,
            severity="high",
            message="No rate limiting detected — API is vulnerable to brute-force and abuse",
            fix="Add rate limiting: slowapi (FastAPI), express-rate-limit (Express), or API gateway-level",
        ))

    if not has_vault_kms and source_files:
        findings.append(Finding(
            category="secrets_management",
            category_id=7,
            check="no_secrets_manager",
            status=CheckStatus.WARN,
            severity="medium",
            message="No secrets manager (Vault, KMS, SSM) detected — secrets may be managed insecurely",
            fix="Use a dedicated secrets manager for production: HashiCorp Vault, AWS KMS, or Doppler",
        ))

    if has_api_routes and not has_hsts:
        findings.append(Finding(
            category="tls",
            category_id=8,
            check="no_hsts",
            status=CheckStatus.WARN,
            severity="medium",
            message="No HSTS header configuration detected — browsers may connect over HTTP first",
            fix="Set Strict-Transport-Security header: max-age=31536000; includeSubDomains",
        ))

    return findings
