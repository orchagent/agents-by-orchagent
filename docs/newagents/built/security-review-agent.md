# Security Review Agent

## Overview

An **orchestrator agent** that performs comprehensive security audits by combining multiple specialized scans. Calls leaf agents for secrets and dependency scanning, plus performs internal pattern-based security checks.

**Type:** Orchestrator (calls other agents)
**Dependencies:** `orchagent/leak-finder@v1`, `orchagent/dep-scanner@v1`

## Related Agents

| Agent | Type | Purpose | Doc |
|-------|------|---------|-----|
| `security-review` | Orchestrator | **THIS AGENT** - combines all security checks | - |
| `leak-finder` | Leaf | Secrets/credentials scanning | Deployed |
| `dep-scanner` | Leaf | Dependency CVE scanning | `dep-scanner-agent.md` |

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                       Caller                           │
│                          │                             │
│                          ▼                             │
│               ┌──────────────────┐                    │
│               │ security-review  │  (orchestrator)    │
│               └────────┬─────────┘                    │
│                        │                              │
│    ┌───────────────────┼───────────────────┐         │
│    ▼                   ▼                   ▼         │
│ ┌──────────┐     ┌──────────┐      ┌────────────┐   │
│ │leak-finder│     │dep-scanner│      │  internal  │   │
│ │ (agent)  │     │ (agent)  │      │   scans    │   │
│ └──────────┘     └──────────┘      └────────────┘   │
│   secrets          CVEs            frontend/API/    │
│                                    logging patterns │
└───────────────────────────────────────────────────────┘
```

## What It Does

| Check Category | Source | Description |
|----------------|--------|-------------|
| **Secrets/Leaks** | `leak-finder` agent | AWS keys, Stripe keys, GitHub tokens, etc. |
| **Dependencies** | `dep-scanner` agent | Known CVEs in npm, pip, Go, Rust packages |
| **Frontend Security** | Internal patterns | Direct DB access, client-side auth, price calculations |
| **API Security** | Internal patterns | Missing rate limiting, missing auth middleware |
| **Logging Issues** | Internal patterns | Sensitive data in logs, verbose error messages |

## Manifest

```json
{
  "name": "security-review",
  "version": "v1",
  "type": "code",
  "description": "Comprehensive security review combining secret scanning, dependency auditing, and code pattern analysis",
  "manifest": {
    "manifest_version": 1,
    "dependencies": [
      { "id": "orchagent/leak-finder", "version": "v1" },
      { "id": "orchagent/dep-scanner", "version": "v1" }
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
  "scan_mode": "full"  // "full" | "secrets-only" | "deps-only" | "patterns-only"
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

**Note:** Build `dep-scanner` first (see `dep-scanner-agent.md`), then build this orchestrator.

### Phase 1: Core Orchestrator
- [ ] Set up FastAPI project structure
- [ ] Implement AgentClient integration
- [ ] Call `leak-finder` and `dep-scanner` agents
- [ ] Add manifest with both dependencies
- [ ] Basic endpoint that combines results from both agents

### Phase 2: Frontend Security Scans (internal)
- [ ] Implement Supabase/Firebase direct access detection
- [ ] Implement client-side auth check detection
- [ ] Implement client-side calculation detection
- [ ] File context awareness (frontend vs backend paths)

### Phase 3: API Security Scans (internal)
- [ ] Implement missing auth middleware detection
- [ ] Implement missing rate limiting detection
- [ ] Support FastAPI, Express, Next.js patterns

### Phase 4: Logging Scans (internal)
- [ ] Implement sensitive data in logs detection
- [ ] Implement verbose error detection

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
