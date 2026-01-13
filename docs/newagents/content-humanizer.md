# Content Humanizer Agent

**Purpose:** Transform AI-generated text into natural, human-sounding writing.

**Why This Agent:** Universal problem — everyone who uses ChatGPT knows AI text sounds robotic. Minimal input (paste text), instant output (rewritten text), clear before/after value demonstration.

---

## Research Findings

### What Makes Text Sound "AI-Generated"

Sources: [Sabrina.dev](https://www.sabrina.dev/p/best-ai-prompt-to-humanize-ai-writing), [Yarnit](https://www.yarnit.app/post/50-prompts-to-humanize-ai-content-tips-tricks-and-more), [Medium](https://medium.com/illumination/how-to-humanize-ai-content-like-a-pro-in-2025-what-actually-works-bc51eab02edc)

**Structural patterns:**
- Perfect grammar with no contractions
- Overly balanced sentence structure
- Seamless, mechanical transitions
- Repetitive paragraph openings

**Word choice markers (over 50 flagged words):**
- Hedging: "can", "may", "just", "that", "very", "really"
- Filler: "literally", "actually", "basically"
- AI favorites: "delve", "embark", "realm", "tapestry", "landscape"
- Hype words: "game-changer", "unlock", "revolutionize", "disruptive", "skyrocket"
- Transitions: "furthermore", "moreover", "however", "in conclusion"

**Punctuation tells:**
- Overuse of em dashes (—)
- Excessive semicolons
- Too-perfect comma placement

### What Makes Text Sound Human

**Rhythm and flow:**
- Varied sentence length (mix short punchy with longer explanatory)
- Occasional sentence fragments for emphasis
- Natural contractions (don't, won't, it's)
- Reading aloud sounds conversational

**Voice markers:**
- Personal opinion ("I think", "in my experience")
- Mild hedging that sounds natural ("if I recall correctly")
- Specific examples over generic statements
- Occasional imperfection (starting sentence with "And" or "But")

**Structural variety:**
- Paragraphs of different lengths
- Not every point perfectly balanced
- Some ideas get more attention than others

---

## Prompt Engineering

### Core Principles

1. **Explicit style rules** — Tell the model exactly what to avoid
2. **Banned word list** — Block the most obvious AI markers
3. **Positive examples** — Show what good looks like, not just what to avoid
4. **Preserve meaning** — Rewrite style, not substance

### Draft System Prompt

```
You are a writing editor who transforms robotic AI-generated text into natural, human-sounding prose.

## Your Task
Rewrite the user's text to sound like a real person wrote it. Preserve the original meaning exactly — only change the style and word choice.

## Rules

NEVER use these words/phrases:
- delve, embark, realm, tapestry, landscape, paradigm
- game-changer, unlock, revolutionize, disruptive, cutting-edge
- furthermore, moreover, in conclusion, it's important to note
- leverage, utilize (use "use" instead)
- very, really, literally, actually, basically
- comprehensive, robust, seamless, innovative

NEVER use:
- Em dashes (—)
- Semicolons (use periods or commas instead)
- More than one exclamation mark total
- Bullet points or numbered lists (convert to prose)

ALWAYS:
- Use contractions (don't, won't, it's, that's)
- Vary sentence length — mix short and long
- Start some sentences with "And" or "But"
- Use "you" and "I" where appropriate
- Prefer simple words over complex ones
- Keep paragraphs under 4 sentences

## Voice
Write like you're explaining something to a smart friend over coffee. Be direct. Skip the throat-clearing. Get to the point.

## Output
Return ONLY the rewritten text. No explanations, no "Here's the revised version", no commentary.
```

### Prompt Refinement Checklist

Before finalizing, test the prompt against:

- [ ] Marketing copy (heavy on hype words)
- [ ] Technical documentation (heavy on jargon)
- [ ] Academic writing (heavy on passive voice)
- [ ] ChatGPT default output (the most common input)
- [ ] Already-human text (should change minimally)

### Edge Cases to Handle

| Input | Expected Behavior |
|-------|-------------------|
| Very short text (<20 words) | Still rewrite, don't refuse |
| Already natural text | Return with minimal changes |
| Text with factual claims | Preserve facts exactly |
| Text with specific names/brands | Keep proper nouns unchanged |
| Non-English text | Politely decline, explain English-only |

---

## Implementation Plan

### Agent Type
**Prompt-based** — No code needed, just system prompt + user input.

### Input Schema
```json
{
  "type": "object",
  "properties": {
    "text": {
      "type": "string",
      "description": "The AI-generated text to humanize",
      "minLength": 10,
      "maxLength": 10000
    }
  },
  "required": ["text"]
}
```

### Output Schema
```json
{
  "type": "object",
  "properties": {
    "humanized_text": {
      "type": "string",
      "description": "The rewritten, human-sounding text"
    }
  },
  "required": ["humanized_text"]
}
```

### Model Selection
- **Recommended:** Claude 3.5 Sonnet or GPT-4o
- **Reasoning:** Need strong instruction-following + good writing quality
- **Not recommended:** Smaller models struggle with nuanced style rules

### Endpoint
```
POST /orchagent/content-humanizer/v1/humanize
```

### Example Request
```json
{
  "text": "In today's rapidly evolving digital landscape, it's important to note that leveraging cutting-edge AI solutions can revolutionize how businesses operate. Furthermore, these innovative tools unlock unprecedented opportunities for growth and efficiency."
}
```

### Example Response
```json
{
  "humanized_text": "AI tools are changing how businesses work. They're making things faster and opening up new ways to grow — if you use them right."
}
```

---

## Testing Strategy

### Quality Metrics

1. **AI detection score** — Run output through GPTZero, Originality.ai
2. **Readability score** — Flesch-Kincaid should stay similar or improve
3. **Meaning preservation** — Human review that facts/intent unchanged
4. **Length ratio** — Output should be similar length (±20%)

### Test Cases

```
Input: "It is important to note that the implementation of this feature will significantly enhance user experience."
Expected: "This feature will make things better for users." (or similar)

Input: "Furthermore, our comprehensive solution leverages cutting-edge technology."
Expected: "Our solution uses modern tech." (or similar)

Input: "The weather is nice today."
Expected: "The weather is nice today." (minimal change — already human)
```

---

## Success Criteria

1. Users paste AI text, get human-sounding output in <3 seconds
2. Output passes AI detection tools >80% of the time
3. Original meaning preserved in 100% of cases
4. Works well for marketing, technical, and casual text

---

## Open Questions

1. **Should we show a diff?** Before/after comparison might increase perceived value
2. **Tone options?** "Professional" vs "Casual" vs "Academic" modes
3. **Length target?** Some users may want shorter output, others same length

---

## Sources

- [Best AI Prompt to Humanize AI Writing](https://www.sabrina.dev/p/best-ai-prompt-to-humanize-ai-writing)
- [50 Prompts to Humanize AI Content](https://www.yarnit.app/post/50-prompts-to-humanize-ai-content-tips-tricks-and-more)
- [How to Humanize AI Content Like a Pro](https://medium.com/illumination/how-to-humanize-ai-content-like-a-pro-in-2025-what-actually-works-bc51eab02edc)
- [Top Prompts to Humanize AI Text](https://justdone.com/blog/writing/prompts-to-humanize-ai-text)
