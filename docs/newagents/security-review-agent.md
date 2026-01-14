# Security Review Agent

## Overview

An **orchestrator agent** that performs comprehensive security audits by combining multiple specialized scans. Calls `leak-finder` for secrets detection and performs additional pattern-based security checks.

**Type:** Orchestrator (calls other agents)
**Dependencies:** `orchagent/leak-finder@v1`

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Caller                         │
│                      │                           │
│                      ▼                           │
│           ┌──────────────────┐                  │
│           │ security-review  │  (orchestrator)  │
│           └────────┬─────────┘                  │
│                    │                            │
│      ┌─────────────┼─────────────┐             │
│      ▼             ▼             ▼             │
│ ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│ │leak-finder│  │ frontend │  │   api    │      │
│ │ (agent)   │  │  checks  │  │  checks  │      │
│ └──────────┘  └──────────┘  └──────────┘      │
│                (internal)    (internal)        │
└─────────────────────────────────────────────────┘
```

## What It Does

| Check Category | Source | Description |
|----------------|--------|-------------|
| **Secrets/Leaks** | `leak-finder` agent | AWS keys, Stripe keys, GitHub tokens, etc. |
| **Frontend Security** | Internal patterns | Direct DB access, client-side auth, price calculations |
| **API Security** | Internal patterns | Missing rate limiting, missing auth middleware |
| **Logging Issues** | Internal patterns | Sensitive data in logs, verbose error messages |
| **Dependencies** | `npm audit` / `pip-audit` | Known CVEs in packages |

## Manifest

```json
{
  "name": "security-review",
  "version": "v1",
  "type": "code",
  "description": "Comprehensive security review combining secret scanning with code pattern analysis",
  "manifest": {
    "manifest_version": 1,
    "dependencies": [
      { "id": "orchagent/leak-finder", "version": "v1" }
    ],
    "max_hops": 2,
    "timeout_ms": 180000,
    "per_call_downstream_cap": 50,
    "downstream_spend_cap": 500
  }
}
```

## API

### Input

```json
{
  "repo_url": "https://github.com/user/repo",
  "scan_mode": "full",  // "full" | "secrets-only" | "code-only"
  "include_deps": true  // Run dependency audit
}
```

### Output

```json
{
  "scan_id": "uuid",
  "findings": {
    "secrets": [...],           // From leak-finder
    "frontend_security": [...], // Direct DB access, client-side auth, etc.
    "api_security": [...],      // Missing rate limits, auth
    "logging": [...],           // Sensitive data in logs
    "dependencies": [...]       // npm/pip audit results
  },
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 3
  },
  "recommendations": [
    "Rotate 2 exposed API keys immediately",
    "Add rate limiting to 3 API endpoints",
    "Move Supabase client to server-side"
  ]
}
```

## Pattern Categories

### Frontend Security Patterns

| Pattern | Severity | What It Catches |
|---------|----------|-----------------|
| Supabase/Firebase client in components | High | Direct DB access from browser |
| `if (user.isPremium)` in .tsx/.jsx | High | Client-side premium gating |
| `localStorage.getItem('premium')` | Critical | Bypassable feature flags |
| Price/cost calculations in components | Medium | Tamperable amounts |

### API Security Patterns

| Pattern | Severity | What It Catches |
|---------|----------|-----------------|
| FastAPI routes without `Depends()` | High | Missing auth |
| Express routes without auth middleware | High | Missing auth |
| No rate limiter import in API files | Medium | Missing rate limiting |

### Logging Patterns

| Pattern | Severity | What It Catches |
|---------|----------|-----------------|
| `console.log(.*password.*)` | High | Secrets in logs |
| `err.stack` in API response | High | Stack traces exposed |
| Raw error object sent to client | Medium | Verbose errors |

## Implementation Plan

### Phase 1: Core Orchestrator
- [ ] Set up FastAPI project structure
- [ ] Implement AgentClient integration (call leak-finder)
- [ ] Add manifest with leak-finder dependency
- [ ] Basic endpoint that returns combined results

### Phase 2: Frontend Security Scans
- [ ] Implement Supabase/Firebase direct access detection
- [ ] Implement client-side auth check detection
- [ ] Implement client-side calculation detection
- [ ] File context awareness (frontend vs backend paths)

### Phase 3: API Security Scans
- [ ] Implement missing auth middleware detection
- [ ] Implement missing rate limiting detection
- [ ] Support FastAPI, Express, Next.js patterns

### Phase 4: Logging & Dependencies
- [ ] Implement sensitive data in logs detection
- [ ] Implement verbose error detection
- [ ] Integrate npm audit / pip-audit
- [ ] Parse and normalize CVE findings

### Phase 5: Polish
- [ ] LLM-powered false positive reduction (like leak-finder)
- [ ] Generate actionable recommendations
- [ ] Add severity scoring and prioritization

## Success Criteria

The agent should catch:
- [ ] All secrets (via leak-finder)
- [ ] Direct Supabase/Firebase usage in React components
- [ ] Client-side premium/admin gating patterns
- [ ] Price calculations in frontend code
- [ ] API routes without rate limiting
- [ ] API routes without auth middleware
- [ ] Sensitive data in console.log statements
- [ ] Stack traces in API responses
- [ ] Known vulnerable dependencies

## References

- Original security checklist: [@burakeregar](https://x.com/burakeregar/status/2011056036673961998)
- OWASP Top 10: https://owasp.org/Top10/
- Orchestration guide: `/docs/orchestration.md`
