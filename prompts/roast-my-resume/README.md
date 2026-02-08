# Roast My Resume

Get brutally honest, entertaining feedback on your resume that exposes the weaknesses you're too polite to hear.

## What It Does

This agent roasts your resume with humor and zero sugar-coating. It delivers harsh but useful feedback that identifies real problems and gives you actionable fixes. Every burn contains genuine insight you can act on.

The agent targets:
- Buzzword abuse ("leveraged", "spearheaded", "synergized")
- Vague accomplishments with no metrics
- Irrelevant skills (yes, we all know Microsoft Word)
- Weak objective statements
- Formatting crimes
- Anything that screams "I used a template"

## Supported Providers

- OpenAI (GPT-4, GPT-4o, etc.)
- Anthropic (Claude 3.5 Sonnet, Claude 3 Opus, etc.)
- Google (Gemini Pro, Gemini Ultra, etc.)

## Input/Output

**Input:**
- `resume_text`: Your resume content (50-15,000 characters)
- `intensity`: How harsh the roast should be (optional, defaults to "medium")

**Output:**
- `roast`: The brutal feedback on your resume
- `score`: Overall score from 1-10
- `top_fix`: The single most important thing to fix

## Intensity Levels

| Level | Description |
|-------|-------------|
| `light` | Playful teasing, still supportive. You'll laugh, not cry. |
| `medium` | Direct criticism with humor. Balanced burns and fixes. |
| `brutal` | No sugar-coating. Every weakness gets called out. |
| `gordon-ramsay` | Surgical destruction followed by exactly one piece of genuine praise. |

## Examples

### Light Roast

**Input:**
```json
{
  "resume_text": "OBJECTIVE: To obtain a challenging position where I can leverage my skills.\n\nSKILLS: Microsoft Office, Communication, Teamwork\n\nEXPERIENCE:\nMarketing Coordinator, ABC Company, 2020-2023\n- Responsible for managing social media accounts\n- Helped with various marketing campaigns",
  "intensity": "light"
}
```

**Output:**
```json
{
  "roast": "Look, your resume is trying its best, and I appreciate the effort. But that objective statement? It's giving 'I googled resume templates at 11pm.' Everyone wants to leverage their skills and find a challenging position — you've basically said 'I would like a job, please.'\n\nYour skills section is adorable. Microsoft Office, Communication, Teamwork... congratulations on being a functioning adult in 2025. Maybe throw in 'can operate a stapler' while you're at it.\n\nThe experience section has potential, but 'responsible for' and 'helped with' are doing all the heavy lifting while contributing nothing. What did you actually accomplish? Any numbers hiding in there?\n\nVerdict: 5/10. It's not bad, it's just... beige. You've got the ingredients for something better here.",
  "score": 5,
  "top_fix": "Replace 'responsible for' and 'helped with' with actual accomplishments and numbers."
}
```

### Medium Roast

**Input:**
```json
{
  "resume_text": "OBJECTIVE: To obtain a challenging position where I can leverage my skills.\n\nSKILLS: Microsoft Office, Communication, Teamwork\n\nEXPERIENCE:\nMarketing Coordinator, ABC Company, 2020-2023\n- Responsible for managing social media accounts\n- Helped with various marketing campaigns",
  "intensity": "medium"
}
```

**Output:**
```json
{
  "roast": "Your objective statement is so generic it could be printed on a participation trophy. 'Leverage my skills and grow professionally' — congratulations, you've described what literally every employed human wants.\n\nThat skills section? 'Microsoft Office, Communication, Teamwork' — you've essentially listed 'I am a functioning adult.' In 2025, saying you know Microsoft Office is like putting 'can operate doorknobs' on your resume. Unless you're doing pivot table wizardry, leave it off.\n\nNow let's talk about your experience. 'Responsible for managing social media accounts' tells me nothing. Did you grow followers? Drive sales? Go viral? Or did you just schedule some posts and call it a day? 'Helped with various marketing campaigns' is the resume equivalent of 'I was in the room when things happened.'\n\nVerdict: 4/10. The bones are there, but this resume is currently a beige wall in human form.",
  "score": 4,
  "top_fix": "Add numbers. Any numbers. Followers grown, campaigns launched, dollars influenced — pick a metric and own it."
}
```

### Gordon Ramsay Mode

**Input:**
```json
{
  "resume_text": "OBJECTIVE: To obtain a challenging position where I can leverage my skills.\n\nSKILLS: Microsoft Office, Communication, Teamwork\n\nEXPERIENCE:\nMarketing Coordinator, ABC Company, 2020-2023\n- Responsible for managing social media accounts\n- Helped with various marketing campaigns",
  "intensity": "gordon-ramsay"
}
```

**Output:**
```json
{
  "roast": "Right, come here. Come here. Look at this. LOOK AT IT. This objective statement — what is this? 'Leverage my skills'? That's not an objective, that's a PRAYER. My nan could write something with more direction, and she's been dead for fifteen years.\n\nSkills. Microsoft Office. MICROSOFT OFFICE. It's 2025! You might as well put 'I know how to breathe' on there. Communication? Teamwork? These aren't skills, these are requirements for existing in society without being arrested.\n\nAnd this experience section — oh, this is where it really falls apart. 'Responsible for managing social media.' Responsible for WHAT exactly? Growing it? Tanking it? Just existing near it? 'Helped with various marketing campaigns' — HELPED? You HELPED? What are you, a golden retriever? Did you fetch the campaigns? Good boy.\n\nBut here's the thing — you worked three years at a real company, in a real role. You DID things. I know you did. So why does this read like you're apologizing for having a job? Stop hiding behind vague nonsense and tell me what you actually accomplished.\n\nVerdict: 3/10. Now get back in there and make it RIGHT.",
  "score": 3,
  "top_fix": "Delete every instance of 'responsible for' and 'helped with' and replace them with specific achievements and metrics."
}
```

## Usage

### With curl

```bash
curl -X POST https://api.orchagent.com/roast-my-resume/v1/roast \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "resume_text": "OBJECTIVE: Seeking opportunities to leverage my skills in a dynamic environment.\n\nSKILLS: Microsoft Office, Excel, Communication, Problem Solving\n\nEXPERIENCE:\nProject Manager, XYZ Corp, 2019-2024\n- Managed multiple projects\n- Coordinated with stakeholders\n- Delivered results on time",
    "intensity": "medium"
  }'
```

## Best Used For

- Getting honest feedback before sending your resume out
- Breaking out of "template thinking"
- Finding the weak spots you've become blind to
- Entertainment (the roasts are pretty funny)
- Motivation to actually fix your resume

## Limitations

- English resumes only
- Maximum 15,000 characters per request
- Works best on text-based resumes (not images or PDFs)
- The roast is harsh by design — if you want gentle feedback, use `light` intensity
