# landing-page-audit

Audits landing pages against a proven 7-section conversion framework. Based on [u/abhishvekc's viral Reddit post](https://reddit.com/r/SideProject/comments/1kicwb0) that hit 836 upvotes (plus 776 on the follow-up — 1,600+ total validating this framework).

## The 7-Section Framework

| # | Section | What it checks |
|---|---------|---------------|
| 1 | Hero | Clear heading + visible CTA + product demo/screenshot |
| 2 | Trust Logos | Company logos, "featured in", or user count metrics |
| 3 | Top Features | 3-5 benefit-led features (not a feature dump) |
| 4 | Differentiation | Why you over alternatives — specific, not generic |
| 5 | Testimonials | Real names, specific results, relevant to target audience |
| 6 | FAQ | Top objections addressed honestly |
| 7 | Closing CTA | Final push with reinforced value prop |

Each section gets **PASS**, **PARTIAL**, or **MISSING** with specific fixes.

## Usage

```bash
# Audit your landing page
orch call orchagent/landing-page-audit --input '{
  "content": "Ship faster with our developer platform. Start Free Trial. Trusted by teams at Stripe, Vercel, and Linear. Features: One-click deploys, Auto-scaling, Built-in CI/CD...",
  "context": "Developer deployment platform for startups"
}'

# With URL reference
orch call orchagent/landing-page-audit --input '{
  "content": "...",
  "context": "SaaS analytics tool",
  "url": "https://myapp.com"
}'
```

## Input

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | string | Yes | All visible text from the landing page, in order |
| `context` | string | No | What the product does and who it's for |
| `url` | string | No | Page URL for reference |

## Output

Each section returns:
- `verdict`: PASS, PARTIAL, or MISSING
- `analysis`: What works and what doesn't (quotes actual copy)
- `fix`: Specific actionable fix

Plus:
- `overall_score`: 0-14 (2 per section)
- `grade`: A (12-14), B (9-11), C (6-8), D (3-5), F (0-2)
- `summary`: Executive summary
- `priority_fixes`: Top 3 changes by impact

## How it differs from landing-page-roast

| | landing-page-audit | landing-page-roast |
|--|---|---|
| **Style** | Structured checklist (constructive) | Brutally honest roast (entertaining) |
| **Framework** | 7 sections with pass/fail | 5 failure categories with scores |
| **Output** | Section-by-section verdicts | Flowing roast text |
| **Best for** | Systematic improvement | Quick gut-check reality |
