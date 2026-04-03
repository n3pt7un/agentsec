# Scan Modes

agentsec supports two scan modes with different trade-offs between speed and depth.

## Offline mode (default)

No API keys required. Uses marker-based detection — probes embed unique string markers in their payloads and check whether the agent echoes them back in its response.

```bash
agentsec scan --adapter langgraph --target ./my_agent.py
```

**Characteristics:**
- Full scan completes in under a second
- No external API calls
- Works in air-gapped environments
- Ideal for CI pipelines
- May produce false negatives on agents with strong output filtering

## Smart mode

LLM-powered attack payload generation and semantic response analysis via [OpenRouter](https://openrouter.ai). Probes generate context-aware payloads tailored to your agent's tools and roles, then use an LLM to analyse the response for vulnerability indicators.

```bash
export AGENTSEC_OPENROUTER_API_KEY=sk-or-...
agentsec scan --smart --adapter langgraph --target ./my_agent.py
```

**Characteristics:**
- Takes 30–120 seconds for a full scan (one LLM call per probe)
- Produces richer, more context-aware findings
- Reduces false negatives on well-guarded agents
- Costs money (see token usage below)
- Requires `AGENTSEC_OPENROUTER_API_KEY`

### Choosing a model

The default attacker model is `anthropic/claude-sonnet-4.6`. Override with `--model`:

```bash
agentsec scan --smart --model anthropic/claude-haiku-4-5-20251001 --target ./my_agent.py
```

Any model available on OpenRouter works. Faster/cheaper models are fine for payload generation; the detection quality matters more.

### Token usage summary

After a smart scan, agentsec prints a usage table:

```
Models   anthropic/claude-sonnet-4.6
Tokens   4,823 in · 1,102 out
Cost     $0.0182
```

Cost is computed from OpenRouter's published pricing.

## Detection mode

Smart mode supports two detection strategies, controlled by `--detection-mode`:

| Mode | Behaviour |
|------|-----------|
| `marker_then_llm` (default) | Fast marker check first; LLM analysis only if marker match is ambiguous |
| `llm_only` | Skip marker check entirely; LLM decides all findings |

```bash
# Pure LLM detection (requires --smart)
agentsec scan --smart --detection-mode llm_only --target ./my_agent.py
```

`llm_only` requires `--smart`. It is slower and more expensive but eliminates false positives caused by agents that echo inputs for other reasons.

## Recommended workflow

| Context | Mode |
|---------|------|
| CI on every PR | Offline (fast, free, catches regressions) |
| Nightly security run | Smart (deeper, worth the cost) |
| Manual investigation | Smart with `--detection-mode llm_only` |
