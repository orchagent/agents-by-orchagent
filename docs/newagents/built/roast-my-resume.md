# Roast My Resume Agent

**Purpose:** Deliver brutally honest, entertaining feedback on resumes that exposes real weaknesses users are too polite to hear.

**Why This Agent:** High entertainment value + genuine utility. Shareable outputs (users screenshot roasts). Solves job anxiety with humor. The "tough love" coaching market is $2.4B — people want honest feedback but rarely get it.

---

## Research Findings

### Why "Roasts" Work Better Than Polite Feedback

Sources: [CyberCorsairs](https://cybercorsairs.com/this-ai-roast-is-insane/), [Medium - Roast Me ChatGPT](https://meganworkmonlarsen.medium.com/roast-me-chatgpt-discovering-your-own-unseen-patterns-11e458a4d04), [Tom's Guide](https://www.tomsguide.com/ai/everyones-asking-chatgpt-to-roast-them-heres-how-to-try-it)

**The psychology:**
- AI's default mode is polite and encouraging — users don't trust it
- Explicitly asking for criticism unlocks honest insights
- Humor makes harsh truths easier to accept
- Entertainment value increases engagement and sharing

**What users actually say:**
> "When I want absolute honest feedback, I go overboard and ask it to 'roast me.' Works very well to find flaws."

> "For even more honest feedback, I ask for the 'Gordon Ramsay Treatment' — the roast is playful, Gordon Ramsay is surgical."

### Effective Roast Techniques

**Intensity levels:**
- **Light roast:** Playful teasing, still supportive
- **Medium roast:** Direct criticism with humor
- **Dark roast:** Brutal honesty, no sugar-coating
- **Gordon Ramsay mode:** Surgical destruction, then rebuild

**Structural approach:**
1. Open with a punchy, memorable observation
2. Identify 3-5 specific weaknesses (not vague)
3. Use analogies and comparisons for impact
4. End with one genuinely actionable insight

**What makes roasts shareable:**
- Specific, quotable lines ("Your skills section reads like a LinkedIn buzzword bingo card")
- Unexpected observations
- Self-aware humor
- A kernel of real truth that stings

### Resume-Specific Weak Points to Target

**Common resume sins:**
- Buzzword overload ("leveraged", "spearheaded", "synergized")
- Vague accomplishments with no metrics
- Objective statements that say nothing
- Skills lists that include "Microsoft Word"
- Job descriptions copied from the posting
- Gaps explained poorly or not at all
- "References available upon request" (everyone knows)
- Comic Sans or weird formatting
- 3+ pages for <10 years experience

**What hiring managers actually care about:**
- Specific numbers and outcomes
- Clear progression
- Relevance to the role
- Easy to scan in 6 seconds

---

## Prompt Engineering

### Core Principles

1. **Permission to be harsh** — The user is explicitly asking for it
2. **Specific over general** — "Your skills section is weak" < "Listing 'proficient in Excel' in 2025 is like bragging you can use a telephone"
3. **Funny but useful** — Every roast should contain actionable truth
4. **Structure the destruction** — Organized roasts are more impactful

### Draft System Prompt

```
You are a brutally honest resume roaster. The user has explicitly asked for harsh, unfiltered feedback on their resume. They want the truth, delivered with humor and zero sugar-coating.

## Your Task
Roast their resume. Be savage, be specific, be memorable. But also be useful — every burn should contain a real insight they can act on.

## Roast Structure

### Opening Line
Start with one punchy, devastating observation. Make it quotable.

### The Roast (3-5 points)
For each weakness:
- Name the problem specifically
- Explain why it's bad (with humor)
- Give the fix in one sentence

Target these areas:
- Buzzword abuse
- Vague accomplishments
- Missing metrics/numbers
- Formatting crimes
- Irrelevant skills
- Weak summary/objective
- Length problems
- Anything that screams "I used a template"

### The Verdict
End with a 1-10 score and one sentence of genuine encouragement buried in the sarcasm.

## Tone Guidelines

DO:
- Use analogies ("This reads like...")
- Be specific to THEIR resume, not generic advice
- Make observations that sting because they're true
- Include at least one backhanded compliment
- Use casual language, contractions, sentence fragments

DON'T:
- Be mean about things they can't change (name, age, gaps due to illness)
- Use profanity or slurs
- Be so harsh it's not funny anymore
- Give generic advice that applies to everyone
- Write more than 400 words total

## Examples of Good Roast Lines

- "Your skills section is a museum of things everyone can do."
- "I've seen more personality in a terms of service agreement."
- "'Responsible for managing projects' — wow, you did your job. Groundbreaking."
- "This objective statement is so generic it could be on a motivational poster in a dentist's office."
- "Three pages for five years of experience? This isn't a memoir."

## Output Format

Return the roast as plain text with clear sections. No markdown headers, no bullet points — write it like you're delivering a comedy set.
```

### Intensity Variants

Consider offering different modes:

**Light Roast:**
```
Add to prompt: "Keep it playful. Tease, don't destroy. The user should laugh, not cry."
```

**Gordon Ramsay Mode:**
```
Add to prompt: "Channel Gordon Ramsay. Be surgical, relentless, but end with exactly one piece of genuine praise that they've earned. Make them want to do better."
```

### Edge Cases to Handle

| Input | Expected Behavior |
|-------|-------------------|
| Actually good resume | Acknowledge it's solid, find smaller nits, be lighter |
| Very junior (student) | Roast the format/presentation, not lack of experience |
| Career changer | Don't mock the pivot, roast how they're presenting it |
| Non-English resume | Politely decline, explain English-only |
| Just a name/no content | Refuse with a joke ("Can't roast what doesn't exist") |

---

## Implementation Plan

### Agent Type
**Prompt-based** — No code needed, just system prompt + user input.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "resume_text": {
      "type": "string",
      "description": "The resume content to roast (paste the text)",
      "minLength": 50,
      "maxLength": 15000
    },
    "intensity": {
      "type": "string",
      "enum": ["light", "medium", "brutal", "gordon-ramsay"],
      "default": "medium",
      "description": "How harsh should the roast be?"
    }
  },
  "required": ["resume_text"]
}
```

### Output Schema
```json
{
  "type": "object",
  "properties": {
    "roast": {
      "type": "string",
      "description": "The brutal feedback on the resume"
    },
    "score": {
      "type": "integer",
      "minimum": 1,
      "maximum": 10,
      "description": "Overall resume score"
    },
    "top_fix": {
      "type": "string",
      "description": "The single most important thing to fix"
    }
  },
  "required": ["roast", "score", "top_fix"]
}
```

### Model Selection
- **Recommended:** Claude 3.5 Sonnet or GPT-4o
- **Reasoning:** Need creativity + instruction-following + appropriate boundaries
- **Not recommended:** Smaller models may be too generic or miss the tone

### Endpoint
```
POST /orchagent/roast-my-resume/v1/roast
```

### Example Request
```json
{
  "resume_text": "OBJECTIVE: To obtain a challenging position where I can leverage my skills and grow professionally.\n\nSKILLS: Microsoft Office, Communication, Teamwork, Problem Solving, Time Management\n\nEXPERIENCE:\nMarketing Coordinator, ABC Company, 2020-2023\n- Responsible for managing social media accounts\n- Helped with various marketing campaigns\n- Worked with cross-functional teams",
  "intensity": "medium"
}
```

### Example Response
```json
{
  "roast": "Your objective statement is so generic it could be printed on a participation trophy. 'Leverage my skills and grow professionally' — congratulations, you've described what literally every employed human wants.\n\nThat skills section? 'Microsoft Office, Communication, Teamwork' — you've essentially listed 'I am a functioning adult.' In 2025, saying you know Microsoft Office is like putting 'can operate doorknobs' on your resume.\n\nNow let's talk about your experience. 'Responsible for managing social media accounts' tells me nothing. Did you grow followers? Drive sales? Go viral? Or did you just schedule some posts and call it a day? 'Helped with various marketing campaigns' is the resume equivalent of 'I was in the room when things happened.'\n\nVerdict: 4/10. The bones are there, but this resume is currently a beige wall in human form. You've played it so safe you've become invisible.",
  "score": 4,
  "top_fix": "Add numbers. Any numbers. Followers grown, campaigns launched, dollars influenced — pick a metric and own it."
}
```

---

## Testing Strategy

### Quality Metrics

1. **Entertainment value** — Would someone screenshot and share this?
2. **Specificity** — Does it reference THEIR resume, not generic advice?
3. **Actionability** — Can they actually fix what you identified?
4. **Appropriate boundaries** — Not cruel, just honest

### Test Cases

```
Input: Generic corporate resume with buzzwords
Expected: Roast the buzzwords specifically, call out vague accomplishments

Input: Student resume with little experience
Expected: Focus on presentation/format, not lack of jobs

Input: Actually strong resume
Expected: Lighter roast, acknowledge quality, find smaller issues

Input: Resume with obvious formatting disasters
Expected: Lead with the visual crimes
```

### Human Review Checklist

- [ ] Is it funny?
- [ ] Is it specific to this resume?
- [ ] Does every criticism have an implicit fix?
- [ ] Would you share this screenshot?
- [ ] Is it harsh but not cruel?

---

## Success Criteria

1. Users laugh (or wince) reading their roast
2. At least 1 line per roast is "screenshot-worthy"
3. Every roast contains actionable feedback
4. Users come back to test improved versions
5. High share rate on social media

---

## Open Questions

1. **Expand to other content?** "Roast My LinkedIn", "Roast My Cover Letter", "Roast My Portfolio"
2. **Before/After mode?** Let users submit revised version for a follow-up roast
3. **Leaderboard?** Show anonymized "worst scores" for entertainment
4. **Tone calibration?** Some users may want even harsher, others may bail — how to calibrate?

---

## Sources

- [Brutal ChatGPT Prompts for Honest Self-Improvement](https://cybercorsairs.com/this-ai-roast-is-insane/)
- [Roast Me, ChatGPT: Discovering Your Own Unseen Patterns](https://meganworkmonlarsen.medium.com/roast-me-chatgpt-discovering-your-own-unseen-patterns-11e458a4d048)
- [Everyone's Asking ChatGPT to Roast Them](https://www.tomsguide.com/ai/everyones-asking-chatgpt-to-roast-them-heres-how-to-try-it)
- [25 Game-Changing ChatGPT Prompts (Reddit)](https://exploreaitogether.com/25-game-changing-chatgpt-prompts-according-to-reddit-power-users/)
- [45+ ChatGPT Prompts for Your Resume](https://www.tealhq.com/post/great-chatgpt-prompts-for-your-resume)
