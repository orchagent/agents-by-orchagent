# Content Humanizer

Transform AI-generated text into natural, human-sounding writing.

## What It Does

This agent rewrites robotic AI-generated text to sound like a real person wrote it. It preserves your original meaning while changing the style and word choice to pass AI detection tools and sound more natural.

The agent specifically:
- Removes overused AI words like "delve", "leverage", "comprehensive", "innovative"
- Replaces stiff transitions like "furthermore" and "moreover" with natural flow
- Adds contractions (don't, won't, it's) that humans actually use
- Varies sentence length and structure
- Converts bullet points and lists into readable prose

## Supported Providers

- OpenAI (GPT-4, GPT-4o, etc.)
- Anthropic (Claude 3.5 Sonnet, Claude 3 Opus, etc.)
- Google (Gemini Pro, Gemini Ultra, etc.)

## Input/Output

**Input:** Text string between 10-10,000 characters

**Output:** Rewritten text that sounds human

## Example

**Input:**
```
In today's rapidly evolving digital landscape, it's important to note that
leveraging cutting-edge AI solutions can revolutionize how businesses operate.
Furthermore, these innovative tools unlock unprecedented opportunities for
growth and efficiency.
```

**Output:**
```
AI tools are changing how businesses work. They're making things faster and
opening up new ways to grow, if you use them right.
```

## Usage

### With curl

```bash
curl -X POST https://api.orchagent.com/content-humanizer/v1/humanize \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "text": "It is important to note that the implementation of this feature will significantly enhance user experience. Furthermore, our comprehensive solution leverages cutting-edge technology."
  }'
```

### Response

```json
{
  "humanized_text": "This feature will make things better for users. And our solution uses modern tech to get it done."
}
```

## Best Used For

- Marketing copy that sounds too "salesy"
- Technical documentation with stiff language
- Blog posts and articles written with AI assistance
- Any text that needs to pass AI detection tools

## Limitations

- English text only
- Maximum 10,000 characters per request
- Preserves meaning but may shorten text slightly
- Works best on prose (not code, data, or structured formats)
