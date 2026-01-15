#!/bin/bash
set -e

MAX_ITERATIONS=${1:-30}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Starting Ralph - Building 4 Showcase Agents"
echo "Working directory: $REPO_ROOT"

cd "$REPO_ROOT"

for i in $(seq 1 $MAX_ITERATIONS); do
  echo "=== Iteration $i ==="

  OUTPUT=$(cat "$SCRIPT_DIR/prompt.md" \
    | claude --dangerously-skip-permissions 2>&1 \
    | tee /dev/stderr) || true

  if echo "$OUTPUT" | grep -q "<promise>COMPLETE</promise>"; then
    echo "All stories complete!"
    exit 0
  fi

  sleep 2
done

echo "Max iterations ($MAX_ITERATIONS) reached"
exit 1
