#!/usr/bin/env bash
# Live scan all 3 harnesses with real LLMs.
# Requires: OPENROUTER_API_KEY set in environment.
#
# Usage: ./scripts/live_scan.sh
#
# Models:
#   Target agents: openai/gpt-4.1-nano (override with AGENTSEC_TARGET_MODEL)
#   Smart probes:  anthropic/claude-sonnet-4 (override with --model)
#   Detection:     anthropic/claude-haiku-4 (default)

set -euo pipefail

# Auto-load .env if present and key not already exported
if [ -z "${OPENROUTER_API_KEY:-}" ] && [ -f .env ]; then
    set -a && source .env && set +a
fi

if [ -z "${OPENROUTER_API_KEY:-}" ]; then
    echo "ERROR: OPENROUTER_API_KEY not set"
    echo "Get a key at https://openrouter.ai/keys"
    exit 1
fi

TARGETS=(
    "tests/targets/supervisor_harness.py"
    "tests/targets/swarm_harness.py"
    "tests/targets/rag_customer_support_harness.py"
    "tests/targets/email_automation_harness.py"
    "tests/targets/rag_research_harness.py"
    "tests/targets/multi_agentic_rag_harness.py"
)

OUTDIR="reports/live-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

for target in "${TARGETS[@]}"; do
    name=$(basename "$target" .py)
    echo "=== Scanning $name (live + smart) ==="
    uv run agentsec scan \
        --adapter langgraph \
        --target "$target" \
        --live \
        --smart \
        --model "anthropic/claude-sonnet-4.6" \
        --format markdown \
        --output "$OUTDIR/$name.md" \
        || echo "WARN: $name scan failed, continuing..."
    echo ""
done

echo "Reports saved to $OUTDIR/"
ls -la "$OUTDIR/"
