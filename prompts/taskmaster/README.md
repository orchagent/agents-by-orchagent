# Taskmaster

A coordinator agent that delegates tasks to sub-agents while keeping its own context clean.

## The Problem

When working on complex tasks, your AI agent's context gets bloated with implementation details, making it less effective at high-level coordination. You end up with an agent that knows everything about the last file it edited but has forgotten the overall goal.

## The Solution

Taskmaster acts as a coordinator that:
- Maintains high-level awareness of the task
- Spawns focused sub-agents for specific work
- Synthesizes results without accumulating details
- Keeps you informed of progress

## Usage

### With OrchAgent CLI
```bash
orch run joe/taskmaster --task "Build a new user dashboard with auth"
```

### Manually (paste into any AI chat)
Copy the contents of `prompt.md` and paste it at the start of your conversation.

## When to Use Taskmaster

- Complex multi-step tasks
- Tasks spanning multiple files or systems
- Work where you want to stay in the loop
- Situations where context management matters

## When NOT to Use Taskmaster

- Simple, single-file changes
- Quick questions or lookups
- Fully automated pipelines (use Ralph instead)

## Related

- **Ralph** - Automated overnight coding loops (external orchestration)
- **OrchAgent code agents** - Deployed API-based orchestration
- **Taskmaster** - Interactive conversation-level orchestration (this)
