# Improve Leak Finder Agent

## Context

Based on a security checklist for "vibe coded" apps (source: [@burakeregar's thread](https://x.com/burakeregar/status/2011056036673961998)), our current security tooling has gaps. This doc outlines improvements to make the secrets-scanner agent a comprehensive security auditor.

## Current State

### What We Have

**1. secrets-scanner agent** (`/agents/secrets-scanner/`)
- Scans for 23+ credential patterns (AWS, Stripe, GitHub, Clerk, Supabase, etc.)
- Git history scanning (catches rotated-but-not-removed secrets)
- LLM-powered false positive reduction via Gemini
- CLI and REST API interfaces

**2. security_reminder_hook** (`.claude/hooks/security_reminder_hook.py`)
- Command injection patterns (system calls, subprocess with shell mode)
- XSS patterns (DOM manipulation, React unsafe HTML, document writing)
- Code injection patterns (dynamic code evaluation)
- SQL injection (string-formatted queries)
- GitHub Actions workflow injection

### Coverage Assessment

| Security Issue | Current Coverage |
|----------------|------------------|
| Exposed API keys/secrets | Full |
| Secrets in git history | Full |
| Command injection | Full (hook) |
| XSS vulnerabilities | Full (hook) |
| SQL injection | Partial (hook) |
| Direct frontend-to-DB | None |
| Missing auth checks | None |
| Client-side premium gating | None |
| Client-side calculations | None |
| Missing rate limiting | None |
| Sensitive data in logs | None |
| Verbose error messages | None |
| Outdated dependencies | None |

## Proposed Improvements

### Priority 1: Frontend Security Patterns

#### 1.1 Direct Database Access from Frontend

Detect when frontend code imports database clients directly instead of going through an API.

**Patterns to detect:**

```python
# Supabase direct client in frontend
FRONTEND_SUPABASE_PATTERNS = [
    {
        "pattern": r"createClient\s*\(\s*['\"]https://.*supabase",
        "file_context": ["src/", "app/", "pages/", "components/"],
        "exclude_context": ["api/", "server/", "backend/", "middleware/"],
        "severity": "high",
        "message": "Supabase client created in frontend code. Use a backend API instead."
    },
    {
        "pattern": r"from\s+['\"]@supabase/supabase-js['\"]",
        "file_context": [".tsx", ".jsx", "components/"],
        "severity": "medium",
        "message": "Supabase SDK imported in component file. Verify this isn't exposing direct DB access."
    }
]

# Firebase direct client in frontend
FRONTEND_FIREBASE_PATTERNS = [
    {
        "pattern": r"getFirestore|collection\(|doc\(",
        "file_context": ["src/", "app/", "pages/", "components/"],
        "exclude_context": ["api/", "server/", "functions/"],
        "severity": "high",
        "message": "Firestore accessed directly from frontend. Use Cloud Functions or API routes."
    }
]
```

#### 1.2 Client-Side Auth/Premium Checks

Detect authorization logic that runs in the browser (easily bypassed).

**Patterns to detect:**

```python
CLIENT_SIDE_AUTH_PATTERNS = [
    {
        "pattern": r"if\s*\(\s*(?:user\.)?(?:isAdmin|isPremium|isSubscribed|hasAccess|role\s*===)",
        "file_context": [".tsx", ".jsx", ".vue", ".svelte"],
        "severity": "high",
        "message": "Client-side authorization check detected. Enforce access control on the server."
    },
    {
        "pattern": r"(?:canAccess|hasPermission|checkAuth)\s*\(\s*\)\s*\?\s*<",
        "file_context": [".tsx", ".jsx"],
        "severity": "high",
        "message": "Conditional rendering based on auth. Server should withhold data, not just hide UI."
    },
    {
        # Detecting feature flags checked client-side
        "pattern": r"localStorage\.getItem\(['\"](?:premium|pro|subscription|tier)['\"]",
        "severity": "critical",
        "message": "Premium status read from localStorage. Users can modify this. Verify server-side."
    }
]
```

#### 1.3 Client-Side Price/Sensitive Calculations

Detect calculations that should happen server-side.

**Patterns to detect:**

```python
CLIENT_SIDE_CALC_PATTERNS = [
    {
        "pattern": r"(?:price|cost|total|amount|discount)\s*[=*+-]",
        "file_context": [".tsx", ".jsx", "components/"],
        "exclude_pattern": r"display|format|render",
        "severity": "medium",
        "message": "Price calculation in frontend. Ensure server validates final amounts."
    },
    {
        "pattern": r"(?:score|points|credits|balance)\s*[=+-]=",
        "file_context": [".tsx", ".jsx"],
        "severity": "medium",
        "message": "Score/credits calculation client-side. Server should be source of truth."
    }
]
```

### Priority 2: API Security Patterns

#### 2.1 Missing Rate Limiting

Detect API endpoints without rate limiting.

**Approach:**
- Scan for route definitions (Express, FastAPI, Next.js API routes)
- Check if rate limiting middleware is applied
- Flag unprotected endpoints

```python
RATE_LIMIT_PATTERNS = [
    {
        # FastAPI without rate limiting
        "pattern": r"@app\.(get|post|put|delete)\(['\"]",
        "negative_pattern": r"@limiter|RateLimiter|slowapi",
        "file_scope": "file",  # Check whole file for limiter
        "severity": "medium",
        "message": "API endpoint without rate limiting. Add slowapi or similar."
    },
    {
        # Express without rate limiting
        "pattern": r"app\.(get|post|put|delete)\(['\"]",
        "negative_pattern": r"rateLimit|express-rate-limit",
        "file_scope": "file",
        "severity": "medium",
        "message": "Express endpoint without rate limiting."
    },
    {
        # Next.js API routes (harder to detect)
        "pattern": r"export\s+(default\s+)?(async\s+)?function\s+(GET|POST|PUT|DELETE|handler)",
        "file_context": ["api/", "app/api/"],
        "severity": "low",
        "message": "API route detected. Verify rate limiting is configured."
    }
]
```

#### 2.2 Missing Auth Middleware

Detect API endpoints that might lack authentication.

```python
MISSING_AUTH_PATTERNS = [
    {
        # FastAPI endpoints without Depends()
        "pattern": r"@app\.(post|put|delete)\([^)]+\)\s*\nasync def \w+\([^)]*\):",
        "negative_pattern": r"Depends\(|current_user|get_user|verify_token",
        "severity": "high",
        "message": "Mutating endpoint without apparent auth dependency."
    },
    {
        # Express without auth middleware
        "pattern": r"app\.(post|put|delete)\(['\"][^'\"]+['\"],\s*(?:async\s*)?\(",
        "negative_pattern": r"authenticate|isAuthenticated|requireAuth|verifyToken",
        "severity": "high",
        "message": "Mutating endpoint without auth middleware in route chain."
    }
]
```

### Priority 3: Logging and Error Handling

#### 3.1 Sensitive Data in Logs

Detect logging of potentially sensitive information.

```python
SENSITIVE_LOGGING_PATTERNS = [
    {
        "pattern": r"console\.log\([^)]*(?:password|secret|token|key|credential|apiKey|api_key)[^)]*\)",
        "severity": "high",
        "message": "Logging potentially sensitive data. Remove before production."
    },
    {
        "pattern": r"logger?\.(info|debug|log)\([^)]*(?:password|secret|token|auth)[^)]*\)",
        "severity": "high",
        "message": "Logger may be exposing sensitive data."
    },
    {
        "pattern": r"print\([^)]*(?:password|secret|token|key)[^)]*\)",
        "file_context": [".py"],
        "severity": "high",
        "message": "Print statement may expose sensitive data."
    }
]
```

#### 3.2 Verbose Error Messages

Detect error handling that exposes internal details.

```python
VERBOSE_ERROR_PATTERNS = [
    {
        "pattern": r"res\.(?:status|json)\([^)]*(?:err\.stack|error\.stack|e\.stack)",
        "severity": "high",
        "message": "Stack trace exposed in API response. Log internally, return generic message."
    },
    {
        "pattern": r"return\s+.*(?:SQLException|DatabaseError|PrismaClient)",
        "severity": "high",
        "message": "Database error details may be exposed to client."
    },
    {
        "pattern": r"(?:catch|except)[^{]*\{[^}]*res\.(send|json)\([^)]*(?:err|error|e)\)",
        "severity": "medium",
        "message": "Raw error object sent to client. Sanitize error responses."
    }
]
```

### Priority 4: Dependency Security

#### 4.1 Outdated Dependencies Check

**Approach:** Not pattern-based. Run as separate check using npm audit and pip-audit tools.

```python
async def check_dependencies(repo_path: str) -> list[Finding]:
    """Check for outdated/vulnerable dependencies."""
    findings = []

    # Check package.json with npm audit
    package_json = repo_path / "package.json"
    if package_json.exists():
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True,
            cwd=repo_path
        )
        vulnerabilities = json.loads(result.stdout)
        # Parse and create findings...

    # Check requirements.txt with pip-audit or safety
    requirements = repo_path / "requirements.txt"
    if requirements.exists():
        result = subprocess.run(
            ["pip-audit", "-r", str(requirements), "--format", "json"],
            capture_output=True
        )
        # Parse and create findings...

    return findings
```

## Implementation Plan

### Phase 1: Extend Pattern Detection
- [ ] Add new pattern categories to `patterns.py`
- [ ] Add file context awareness (frontend vs backend detection)
- [ ] Add negative pattern matching (detect absence of security measures)

### Phase 2: New Scan Modes
- [ ] Add `--security-audit` flag for full vulnerability scan (not just secrets)
- [ ] Add `--frontend-only` flag for client-side security focus
- [ ] Add `--api-only` flag for backend security focus

### Phase 3: Dependency Scanning
- [ ] Integrate npm audit / pip-audit
- [ ] Add findings for known CVEs
- [ ] Track dependency age (warn on very old packages)

### Phase 4: LLM-Enhanced Analysis
- [ ] Use LLM to understand auth flow (not just pattern matching)
- [ ] Have LLM trace data flow from frontend to backend
- [ ] Detect architectural issues that patterns cannot catch

## New API Response Format

```json
{
  "scan_id": "uuid",
  "mode": "security-audit",
  "findings": {
    "secrets": [...],
    "frontend_security": [...],
    "api_security": [...],
    "logging": [...],
    "dependencies": [...]
  },
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 3
  },
  "recommendations": [
    "Add rate limiting to 3 API endpoints",
    "Move Supabase client to server-side",
    "Remove 2 console.log statements with sensitive data"
  ]
}
```

## Success Criteria

The improved agent should catch:
- [ ] Direct Supabase/Firebase usage in React components
- [ ] Client-side premium/admin gating patterns
- [ ] Price calculations in frontend code
- [ ] API routes without rate limiting
- [ ] API routes without auth middleware
- [ ] Sensitive data in console.log statements
- [ ] Stack traces in API responses
- [ ] Known vulnerable dependencies

## References

- Original thread: [@burakeregar](https://x.com/burakeregar/status/2011056036673961998)
- OWASP Top 10: https://owasp.org/Top10/
- CWE Top 25: https://cwe.mitre.org/top25/
