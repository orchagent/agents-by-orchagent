# Backend Security Auditor

Inspired by [@0xlelouch_](https://x.com/0xlelouch_/status/2016874653059522802)'s backend security hardening guide.

Audits backend codebases against a **15-point security hardening checklist**, covering authentication, input validation, SQL safety, secrets management, and more.

## What It Checks

| # | Category | What It Looks For |
|---|----------|-------------------|
| 1 | **Authentication & Password Policy** | Weak hashing (MD5/SHA1), missing MFA, no password validation |
| 2 | **Access Tokens & Refresh Tokens** | JWT without expiry, no refresh rotation, no revocation |
| 3 | **Authorization Checks** | Unprotected routes, missing RBAC/ABAC |
| 4 | **Input Validation & Output Encoding** | No validation library, XSS patterns, code/command injection |
| 5 | **SQL Safety** | String-built queries, f-string SQL, no parameterized queries |
| 6 | **Rate Limiting & Abuse Protection** | No rate limiting middleware |
| 7 | **Secrets Management** | Hardcoded secrets, exposed .env files, no Vault/KMS |
| 8 | **TLS Everywhere** | HTTP URLs, disabled TLS verification, no HSTS |
| 9 | **Safe File Handling** | Uploads without size limits or type validation |
| 10 | **Logging & Audit Trails** | Sensitive data in logs, no audit trail, no structured logging |
| 11 | **Error Handling** | Stack traces exposed, debug mode, no global error handler |
| 12 | **Dependency Hygiene** | Missing lockfiles, deprecated packages, no .gitignore |
| 13 | **Data Protection** | No encryption, PII without field-level encryption |
| 14 | **Secure API Defaults** | CORS wildcard, no pagination, missing security headers |
| 15 | **Security Observability** | No monitoring, no auth failure alerts, no health check |

## Usage

```bash
# Upload a zip/tar.gz of your codebase (works for private code)
orch call orchagent/backend-security-auditor --file my-project.zip

# Scan a public GitHub repo
orch call orchagent/backend-security-auditor --data '{"repo_url": "https://github.com/user/repo"}'

# Exclude directories
orch call orchagent/backend-security-auditor --file my-project.zip --data '{"exclude": ["vendor", "dist"]}'
```

You can also upload your codebase directly on the [web UI](https://orchagent.io/agents/orchagent/backend-security-auditor) — just drag and drop a zip file.

## Output

Returns a structured report with:
- **Score** (0-100) and letter grade (A-F)
- **Checklist** — PASS/WARN/FAIL for each of the 15 categories
- **Critical issues** with file locations and fix suggestions
- **Recommendations** prioritized by severity

## Supported Languages

- Python (FastAPI, Django, Flask)
- JavaScript/TypeScript (Express, Next.js, Node.js)

## Credits

Based on the backend security hardening checklist by [@0xlelouch_](https://x.com/0xlelouch_/status/2016874653059522802).
