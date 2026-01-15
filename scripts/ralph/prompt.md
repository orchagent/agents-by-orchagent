# Ralph Agent Instructions - Building OrchAgent Showcase Agents

## Your Task

You are building 4 showcase agents for the OrchAgent marketplace. Each iteration, complete ONE user story.

## Workflow

1. Read `scripts/ralph/prd.json` - find the highest priority story where `passes: false`
2. Read `scripts/ralph/progress.txt` - check Codebase Patterns first
3. Verify you're on branch `ralph/showcase-agents` (create if needed)
4. Implement that ONE story completely
5. For code-based agents: run tests with `python -m pytest tests/`
6. Commit: `feat: [ID] - [Title]`
7. Update prd.json: set `passes: true` for the completed story
8. Append learnings to progress.txt

## Reference Materials

- **Existing agent pattern:** `leak-finder/` - use this as your template
- **Agent specs:** `docs/newagents/` - detailed requirements for each agent
  - `dep-scanner-agent.md` - Code-based leaf agent
  - `security-review-agent.md` - Code-based orchestrator agent
  - `content-humanizer.md` - Prompt-based agent
  - `roast-my-resume.md` - Prompt-based agent

## Agent Types

### Code-based Agents (dep-scanner, security-review)

Create full project structure:
```
agent-name/
├── orchagent.json      # Agent manifest
├── pyproject.toml      # Python dependencies
├── Dockerfile          # Container config
├── README.md           # Documentation
├── src/agent_name/
│   ├── __init__.py
│   ├── main.py         # FastAPI app
│   ├── models.py       # Pydantic models
│   └── [business logic files]
└── tests/
    └── test_main.py
```

### Prompt-based Agents (content-humanizer, roast-my-resume)

Minimal structure:
```
agent-name/
├── orchagent.json      # Contains prompt, input_schema, output_schema
└── README.md           # Usage examples
```

## orchagent.json Format

For code-based:
```json
{
  "name": "agent-name",
  "version": "v1",
  "type": "code",
  "description": "What it does",
  "supported_providers": ["any"],
  "tags": ["tag1", "tag2"],
  "default_endpoint": "scan",
  "source_url": "git+https://github.com/jp730/agents-by-orchagent.git#subdirectory=agent-name",
  "run_command": "python3 -m agent_name.cli"
}
```

For prompt-based:
```json
{
  "name": "agent-name",
  "version": "v1",
  "type": "prompt",
  "description": "What it does",
  "supported_providers": ["openai", "anthropic", "gemini"],
  "tags": ["tag1", "tag2"],
  "prompt": "Your system prompt here...",
  "input_schema": { ... },
  "output_schema": { ... }
}
```

## Progress Format

APPEND to progress.txt after each story:

```
## [Date] - [Story ID]
- What was implemented
- Files changed
- **Learnings:**
  - Patterns discovered
  - Gotchas encountered
---
```

## Stop Condition

If ALL stories in prd.json have `passes: true`, reply ONLY with:

<promise>COMPLETE</promise>

Otherwise end normally after completing one story.

## Important Rules

1. Complete ONE story per iteration - don't skip ahead
2. Follow the leak-finder patterns exactly for code structure
3. Read the spec in docs/newagents/ before implementing each agent
4. For code agents: tests must pass before marking story complete
5. Always commit after completing a story
6. Don't modify completed stories (passes: true)
