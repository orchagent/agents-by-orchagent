"""Environment variable exposure scanner.

Detects:
- NEXT_PUBLIC_ env vars containing sensitive data (API keys, secrets, DB URLs)
- .env files committed to repo
- process.env usage in client components leaking server secrets
- next.config.js env/publicRuntimeConfig exposing secrets
"""

import re
from pathlib import Path

from ..models import Finding, FindingCategory, Severity
from .common import walk_source_files, read_file_lines, is_client_component


# Sensitive env var name patterns (should NOT be in NEXT_PUBLIC_)
SENSITIVE_ENV_NAMES = re.compile(
    r'NEXT_PUBLIC_(?:'
    r'.*(?:SECRET|PRIVATE|PASSWORD|PASSWD|DB_URL|DATABASE_URL|'
    r'SERVICE_KEY|SERVICE_ROLE|ADMIN_KEY|MASTER_KEY|'
    r'SUPABASE_SERVICE|FIREBASE_ADMIN|AWS_SECRET|'
    r'STRIPE_SECRET|OPENAI_API|ANTHROPIC_API|GITHUB_TOKEN|'
    r'JWT_SECRET|SESSION_SECRET|ENCRYPTION_KEY|SIGNING_KEY)'
    r')',
    re.IGNORECASE,
)

# Pattern for process.env access to non-public vars in client code
PROCESS_ENV_SERVER_VAR = re.compile(
    r'process\.env\.(?!NEXT_PUBLIC_|NODE_ENV|VERCEL|CI)([A-Z_]+)',
)

# Pattern for env config in next.config
NEXT_CONFIG_ENV_PATTERN = re.compile(
    r'(?:env\s*:|publicRuntimeConfig\s*:)\s*\{',
)

# .env file names
ENV_FILE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    ".env.test",
}

# Sensitive value patterns inside env files
SENSITIVE_VALUE_PATTERNS = [
    re.compile(r'(?:SECRET|PRIVATE|PASSWORD|TOKEN|KEY|CREDENTIAL)\s*=\s*\S+', re.IGNORECASE),
    re.compile(r'(?:DATABASE_URL|DB_URL|REDIS_URL|MONGO_URI)\s*=\s*\S+', re.IGNORECASE),
    re.compile(r'sk[-_](?:live|test|prod)', re.IGNORECASE),
    re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]+'),
]

# Sensitive variable names exposed via next.config env/publicRuntimeConfig (JS object syntax uses ":")
SENSITIVE_CONFIG_ENV_NAMES = re.compile(
    r'(?:SECRET|PRIVATE|PASSWORD|TOKEN|DATABASE_URL|DB_URL|REDIS_URL|MONGO_URI|'
    r'SERVICE_KEY|SERVICE_ROLE|ADMIN_KEY|MASTER_KEY|AWS_SECRET|'
    r'STRIPE_SECRET|OPENAI_API|ANTHROPIC_API|JWT_SECRET|SESSION_SECRET|'
    r'ENCRYPTION_KEY|SIGNING_KEY)\s*[:\s]',
    re.IGNORECASE,
)


def scan_env_patterns(
    project_path: str | Path,
    base_path: str | Path | None = None,
) -> list[Finding]:
    """Scan for environment variable exposure issues."""
    project_path = Path(project_path)
    base_path = Path(base_path) if base_path else project_path
    findings: list[Finding] = []

    # 1. Check for .env files committed to repo
    for env_name in ENV_FILE_NAMES:
        env_path = project_path / env_name
        if env_path.exists():
            try:
                display = str(env_path.relative_to(base_path))
            except ValueError:
                display = str(env_path)

            content = ""
            try:
                content = env_path.read_text(encoding="utf-8", errors="ignore")
            except (IOError, OSError):
                pass

            has_secrets = any(p.search(content) for p in SENSITIVE_VALUE_PATTERNS)

            if has_secrets:
                findings.append(Finding(
                    category=FindingCategory.env_exposure,
                    severity=Severity.critical,
                    title=f"Sensitive data in {env_name}",
                    file=display,
                    description=(
                        f"{env_name} contains secrets and may be committed to version control. "
                        "Secrets in .env files checked into git are exposed to anyone with repo access."
                    ),
                    remediation=(
                        f"1. Add {env_name} to .gitignore\n"
                        f"2. Remove from git history: git filter-repo --path {env_name} --invert-paths\n"
                        "3. Rotate all exposed secrets immediately"
                    ),
                    cwe="CWE-798",
                ))
            else:
                findings.append(Finding(
                    category=FindingCategory.env_exposure,
                    severity=Severity.medium,
                    title=f"{env_name} file present in project",
                    file=display,
                    description=f"{env_name} exists in the project root. Verify it is in .gitignore.",
                    remediation=f"Add {env_name} to .gitignore if not already present.",
                    cwe="CWE-538",
                ))

            # Check for NEXT_PUBLIC_ vars with sensitive names inside .env files
            for line_idx, env_line in enumerate(content.splitlines(), start=1):
                env_match = SENSITIVE_ENV_NAMES.search(env_line)
                if env_match:
                    findings.append(Finding(
                        category=FindingCategory.env_exposure,
                        severity=Severity.critical,
                        title="Sensitive data in NEXT_PUBLIC_ variable",
                        file=display,
                        line=line_idx,
                        description=(
                            f"Environment variable {env_match.group(0)} is prefixed with NEXT_PUBLIC_, "
                            "which exposes it to the browser. Secrets must never use the NEXT_PUBLIC_ prefix."
                        ),
                        remediation=(
                            f"Remove the NEXT_PUBLIC_ prefix from {env_match.group(0)} and access it "
                            "only in server-side code (API routes, server components, getServerSideProps)."
                        ),
                        cwe="CWE-200",
                    ))

    # 2. Scan for NEXT_PUBLIC_ vars with sensitive names
    for file_path in walk_source_files(project_path):
        lines = read_file_lines(file_path)
        if not lines:
            continue

        try:
            display_path = str(file_path.relative_to(base_path))
        except ValueError:
            display_path = str(file_path)

        for line_num, line in lines:
            match = SENSITIVE_ENV_NAMES.search(line)
            if match:
                findings.append(Finding(
                    category=FindingCategory.env_exposure,
                    severity=Severity.critical,
                    title="Sensitive data in NEXT_PUBLIC_ variable",
                    file=display_path,
                    line=line_num,
                    description=(
                        f"Environment variable {match.group(0)} is prefixed with NEXT_PUBLIC_, "
                        "which exposes it to the browser. Secrets must never use the NEXT_PUBLIC_ prefix."
                    ),
                    remediation=(
                        f"Remove the NEXT_PUBLIC_ prefix from {match.group(0)} and access it "
                        "only in server-side code (API routes, server components, getServerSideProps)."
                    ),
                    cwe="CWE-200",
                ))

    # 3. Check for process.env server vars in client components
    for file_path in walk_source_files(project_path):
        lines = read_file_lines(file_path)
        if not lines:
            continue

        content = "\n".join(line for _, line in lines)

        if not is_client_component(file_path, content):
            continue

        try:
            display_path = str(file_path.relative_to(base_path))
        except ValueError:
            display_path = str(file_path)

        for line_num, line in lines:
            match = PROCESS_ENV_SERVER_VAR.search(line)
            if match:
                var_name = match.group(1)
                findings.append(Finding(
                    category=FindingCategory.env_exposure,
                    severity=Severity.high,
                    title="Server env var accessed in client component",
                    file=display_path,
                    line=line_num,
                    description=(
                        f"process.env.{var_name} is accessed in a client component. "
                        "Server-only environment variables are undefined in the browser but "
                        "may be inlined at build time, leaking secrets into client bundles."
                    ),
                    remediation=(
                        f"Move the usage of process.env.{var_name} to a server component, "
                        "API route, or server action. If it must be in the client, use "
                        "NEXT_PUBLIC_ prefix (only for non-sensitive values)."
                    ),
                    cwe="CWE-200",
                ))

    # 4. Check next.config.js for exposed env vars
    for config_name in ("next.config.js", "next.config.ts", "next.config.mjs"):
        config_path = project_path / config_name
        if not config_path.exists():
            continue

        lines = read_file_lines(config_path)
        content = "\n".join(line for _, line in lines)

        try:
            display_path = str(config_path.relative_to(base_path))
        except ValueError:
            display_path = str(config_path)

        if NEXT_CONFIG_ENV_PATTERN.search(content):
            for line_num, line in lines:
                matched = False
                # Check .env-style patterns (for inline values)
                for sv_pattern in SENSITIVE_VALUE_PATTERNS:
                    if sv_pattern.search(line):
                        matched = True
                        break
                # Check config-style patterns (JS object key: value)
                if not matched and SENSITIVE_CONFIG_ENV_NAMES.search(line):
                    matched = True
                if matched:
                    findings.append(Finding(
                        category=FindingCategory.env_exposure,
                        severity=Severity.high,
                        title="Sensitive value in next.config env/publicRuntimeConfig",
                        file=display_path,
                        line=line_num,
                        description=(
                            "next.config.js env or publicRuntimeConfig exposes values to "
                            "the client bundle. Secrets here will be visible in the browser."
                        ),
                        remediation=(
                            "Remove secrets from env/publicRuntimeConfig in next.config.js. "
                            "Access them only via server-side code using process.env directly."
                        ),
                        cwe="CWE-200",
                    ))

    return findings
