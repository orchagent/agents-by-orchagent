# Ralph Agent Instructions - Secrets Scanner

## Your Task

1. Read `scripts/ralph/prd.json` for user stories
2. Read `scripts/ralph/progress.txt` (check Codebase Patterns first)
3. Ensure you're on the correct branch (`feature/secrets-scanner`)
4. Pick highest priority story where `passes: false`
5. Implement that ONE story completely
6. Verify all acceptance criteria are met
7. Commit: `feat: [ID] - [Title]`
8. Update prd.json: set `passes: true` for that story
9. Append learnings to progress.txt

## Project Context

You're building a secrets scanner agent for OrchAgent platform.
- Location: `/agents/secrets-scanner/`
- Pattern: Follow existing agents in `/agents/billing-doc-analyzer/` and `/agents/invoice-scanner/`
- FastAPI for API, argparse for CLI
- Gemini for LLM analysis (BYOK - user provides key)

## Progress Format

APPEND to progress.txt:

---
## [Date] - [Story ID]
- What was implemented
- Files created/changed
- **Learnings:**
  - Patterns discovered
  - Gotchas encountered
---

## Codebase Patterns

Add reusable patterns to the TOP of progress.txt under "## Codebase Patterns":
- Document useful imports, conventions, etc.
- Future iterations will read this first

## Verification

Before marking a story as passing:
1. Run any relevant tests
2. Verify imports work: `python -c "from secrets_scanner.module import ..."`
3. Check acceptance criteria are ALL met

## Stop Condition

If ALL stories in prd.json have `passes: true`, reply:
<promise>COMPLETE</promise>

Otherwise, end your turn normally after completing one story.
