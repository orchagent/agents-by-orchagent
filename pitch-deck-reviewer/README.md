# pitch-deck-reviewer

Review your startup pitch deck against 30 rules distilled from hundreds of investor meetings.

Based on [u/duygudulger's viral Reddit post](https://reddit.com/r/startups/comments/1pylg24) (335 upvotes, 129 comments) and [u/ssk012's investor framework](https://reddit.com/r/startups/comments/1l9p55o) (85 upvotes, 72 comments).

## Usage

```bash
orch call orchagent/pitch-deck-reviewer --input '{
  "deck_content": "Slide 1: AcmeCo - The Future of Hiring\nSlide 2: Problem - Hiring takes too long...\nSlide 3: Solution - Our AI-powered platform...",
  "company_context": "We help small businesses hire faster by matching them with pre-vetted candidates",
  "stage": "seed",
  "ask_amount": "$1.5M"
}'
```

## What It Reviews

| Category | What It Checks |
|----------|---------------|
| Problem Slide | Does it make investors lean forward? Personal connection? Clear pain? |
| Traction | Numbers with context (growth, unit economics) vs vanity metrics |
| Market Sizing | Bottom-up math vs Statista copy-paste |
| Team | "Why you, why now" vs LinkedIn padding |
| The Ask | Milestone-linked vs "we need money for stuff" |
| Storytelling | Clarity, benefits vs features, one idea per slide |
| Design Signals | Consistency, density, readability |
| Anti-Patterns | "Platform", "Uber for X", fake TAM, premature exit strategy |

## Output

```json
{
  "review": "Let's start with your problem slide. You wrote 'Hiring takes too long' which is about as compelling as...",
  "overall_score": 5,
  "problem_score": 4,
  "traction_score": 3,
  "market_score": 6,
  "team_score": 5,
  "ask_score": 4,
  "storytelling_score": 5,
  "design_signals_score": 6,
  "anti_patterns_found": [
    "Uses 'platform' to describe product",
    "AI-powered as differentiator without substance",
    "Traction numbers without growth context"
  ],
  "verdict": "This deck explains what you built but never explains why anyone should care.",
  "top_fix": "Rewrite slide 2 to lead with the specific pain your customers told you about, not a generic industry observation.",
  "investor_readiness": "needs-work"
}
```

## Tips

- **Label your slides** — "Slide 1: Cover", "Slide 2: Problem" etc. helps the reviewer follow your structure
- **Include all text** — don't skip footnotes, chart labels, or small print. Those details matter
- **Add company_context** — without it, the reviewer can't judge if your hero communicates what you do
- **Set your stage** — expectations differ drastically between pre-seed and Series A

## Skills Used

- `orchagent/feedback-roast-style` — delivers honest feedback with humor and actionable rewrites
