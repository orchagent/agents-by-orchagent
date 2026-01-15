# linkedin-optimizer

Optimize LinkedIn profiles and posts for visibility and engagement.

## Usage

```bash
orch call orchagent/linkedin-optimizer --input '{
  "content_type": "headline",
  "current_content": "Senior Software Engineer | Passionate about building great products | MBA",
  "context": "I specialize in developer tools and want to attract startup opportunities"
}'
```

## Output

```json
{
  "optimized": "Building DevTools that mass dev teams faster | Ex-Stripe, shipped 3 tools to 10K+ users",
  "changes_made": [
    "Removed 'passionate' - show don't tell",
    "Added specific metric (10K+ users)",
    "Led with what you DO not your title",
    "Removed MBA - not relevant to target audience"
  ],
  "score_before": 4,
  "score_after": 8
}
```

## Skills Used

- `orchagent/natural-writing-style` - Ensures content sounds human, not corporate
