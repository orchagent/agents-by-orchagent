# Dep Scanner Agent

## Overview

A **leaf agent** that scans project dependencies for known vulnerabilities (CVEs). Runs `npm audit`, `pip-audit`, and similar tools to identify outdated or insecure packages.

**Type:** Leaf (no dependencies)
**Called by:** `security-review` orchestrator

## Related Agents

```
security-review (orchestrator)
    ├── leak-finder     ← secrets/credentials
    ├── dep-scanner     ← THIS AGENT (CVEs in dependencies)
    └── internal scans  ← frontend/API/logging patterns
```

## What It Does

| Package Manager | Tool Used | What It Checks |
|-----------------|-----------|----------------|
| npm/yarn/pnpm | `npm audit` | Known CVEs in node_modules |
| pip | `pip-audit` | Known CVEs in Python packages |
| Go | `govulncheck` | Known CVEs in Go modules |
| Rust | `cargo audit` | Known CVEs in Cargo dependencies |

## API

### Input

```json
{
  "repo_url": "https://github.com/user/repo",
  "package_managers": ["npm", "pip"],  // Optional, auto-detect if omitted
  "severity_threshold": "medium"        // "low" | "medium" | "high" | "critical"
}
```

### Output

```json
{
  "scan_id": "uuid",
  "detected_managers": ["npm", "pip"],
  "findings": [
    {
      "package": "lodash",
      "version": "4.17.15",
      "severity": "high",
      "cve": "CVE-2021-23337",
      "title": "Command Injection",
      "fixed_in": "4.17.21",
      "recommendation": "Run: npm update lodash"
    },
    {
      "package": "requests",
      "version": "2.25.0",
      "severity": "medium",
      "cve": "CVE-2023-32681",
      "title": "Unintended Leak of Proxy-Authorization Header",
      "fixed_in": "2.31.0",
      "recommendation": "Run: pip install --upgrade requests"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 3,
    "total_packages_scanned": 847
  }
}
```

## Implementation Plan

### Phase 1: npm Support
- [ ] Clone repo to temp directory
- [ ] Detect package.json / package-lock.json
- [ ] Run `npm audit --json`
- [ ] Parse and normalize output to standard format

### Phase 2: pip Support
- [ ] Detect requirements.txt / pyproject.toml / Pipfile
- [ ] Run `pip-audit --format json`
- [ ] Parse and normalize output

### Phase 3: Additional Managers
- [ ] Add Go support (`govulncheck`)
- [ ] Add Rust support (`cargo audit`)
- [ ] Auto-detect which managers are present

### Phase 4: Polish
- [ ] Add severity filtering
- [ ] Generate upgrade commands for each finding
- [ ] Track dependency age (warn on very old packages even without CVEs)
- [ ] Cache vulnerability databases for faster scans

## Standalone Usage

Can be called directly (not just via security-review):

```bash
curl -X POST https://api.orchagent.io/orchagent/dep-scanner/v1/scan \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"repo_url": "https://github.com/user/repo"}'
```

## Success Criteria

- [ ] Detects CVEs in npm packages
- [ ] Detects CVEs in pip packages
- [ ] Returns actionable upgrade commands
- [ ] Handles repos with multiple package managers
- [ ] Completes scan in < 60 seconds for typical repos

## References

- npm audit docs: https://docs.npmjs.com/cli/v8/commands/npm-audit
- pip-audit: https://github.com/pypa/pip-audit
- NVD (vulnerability database): https://nvd.nist.gov/
