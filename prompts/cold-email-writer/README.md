# cold-email-writer

Write personalized cold outreach emails that get responses.

## Usage

```bash
orch call orchagent/cold-email-writer --input '{
  "recipient": "Sarah Chen, VP Engineering at Stripe, posts about developer experience on LinkedIn",
  "sender_context": "I'm a DevTools founder, previously eng at Vercel",
  "goal": "Get feedback on my CLI tool for API testing"
}'
```

## Output

```json
{
  "subject": "Quick question about API testing at Stripe",
  "body": "Hi Sarah,\n\nYour post about reducing integration test flakiness hit home...",
  "personalization_notes": "Referenced her LinkedIn post about testing"
}
```

## Skills Used

- `orchagent/natural-writing-style` - Ensures email sounds human, not AI-generated
