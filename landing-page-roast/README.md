# landing-page-roast

Brutally honest landing page audits across 5 categories. Based on [u/thicc_fruits' viral Reddit post](https://reddit.com/r/SaaS/comments/1k6paz3) about the 5 recurring failures in SaaS landing pages.

## What it checks

| Category | What it looks for |
|----------|-------------------|
| Hero Clarity | Can a visitor explain what you do in 5 seconds? |
| Outcomes vs Features | Are you selling results or listing specs? |
| Personality | Does the copy have a voice, or could it be anyone's page? |
| Social Proof | Testimonials, logos, numbers, case studies |
| CTA Effectiveness | Are CTAs specific, visible, and clear about what happens next? |

## Usage

```bash
# Basic roast
orchagent call orchagent/landing-page-roast --input '{
  "content": "Supercharge your workflow with our AI-powered platform. Features: Smart Analytics, Team Collaboration, Real-time Sync. Get Started Free."
}'

# With product context (helps judge hero clarity)
orchagent call orchagent/landing-page-roast --input '{
  "content": "Supercharge your workflow with our AI-powered platform...",
  "context": "Project management tool for remote teams",
  "intensity": "brutal"
}'
```

## Input

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | string | Yes | Landing page copy (all visible text) |
| `context` | string | No | What the product actually does |
| `url` | string | No | Page URL for reference |
| `intensity` | enum | No | `light`, `medium` (default), `brutal`, `gordon-ramsay` |

## Output

| Field | Type | Description |
|-------|------|-------------|
| `roast` | string | Full roast covering all 5 categories with quotes and rewrites |
| `overall_score` | integer | 1-10 overall score |
| `hero_clarity_score` | integer | 1-10 hero section score |
| `outcomes_score` | integer | 1-10 outcomes vs features score |
| `personality_score` | integer | 1-10 copy personality score |
| `social_proof_score` | integer | 1-10 social proof score |
| `cta_score` | integer | 1-10 CTA effectiveness score |
| `verdict` | string | One-sentence summary |
| `top_fix` | string | Most impactful change to make first |

## Scoring

- **1-3**: Actively hurting conversions
- **4-5**: Below average, generic, forgettable
- **6-7**: Decent, gets the basics right
- **8-9**: Strong, clear, compelling
- **10**: Exceptional (rare)
