<!-- AUTO-GENERATED — do not edit directly. Re-run scripts/wiki/generate_cli_reference.py -->

# CLI Commands

Full flag reference for all agentsec commands.

> For narrative usage examples, see [CLI Reference](../using/CLI-Reference).

## `agentsec scan`

Scan a multi-agent system for OWASP Agentic vulnerabilities.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--adapter` | `TEXT` | `langgraph` | Adapter to use (e.g. langgraph) |
| `--target` | `TEXT` | — | Path to target agent system |
| `--categories` | `TEXT` | — | Comma-separated OWASP categories |
| `--probes` | `TEXT` | — | Comma-separated probe IDs |
| `--output` | `TEXT` | — | Write report to this file |
| `--format` | `TEXT` | `markdown` | Report format: markdown, json, sarif |
| `--verbose` | `flag` | `no-verbose` | Verbose output — print each finding as it completes |
| `--vulnerable` | `flag` | `vulnerable` | Pass vulnerable flag to fixture builders |
| `--smart` | `flag` | `no-smart` | Use LLM-powered smart payloads via OpenRouter |
| `--model` | `TEXT` | `anthropic/claude-sonnet-4.6` | OpenRouter model identifier |
| `--live` | `flag` | `no-live` | Use a real LLM via OpenRouter for target agents |
| `--target-model` | `TEXT` | — | OpenRouter model ID for target agents (live mode only) |
| `--detection-mode` | `TEXT` | `marker_then_llm` | Detection strategy: 'marker_then_llm' (default) or 'llm_only'. 'llm_only' requires --smart. |

---

## `agentsec probe`

Run a single probe for debugging.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--adapter` | `TEXT` | `langgraph` | Adapter to use (e.g. langgraph) |
| `--target` | `TEXT` | — | Path to target agent system |
| `--vulnerable` | `flag` | `vulnerable` | Pass vulnerable flag to fixture builders |
| `--smart` | `flag` | `no-smart` | Use LLM-powered smart payloads via OpenRouter |
| `--model` | `TEXT` | `anthropic/claude-sonnet-4.6` | OpenRouter model identifier |
| `--live` | `flag` | `no-live` | Use a real LLM via OpenRouter for target agents |
| `--target-model` | `TEXT` | — | OpenRouter model ID for target agents (live mode only) |

---

## `agentsec probes list`

List available probes.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--category` | `TEXT` | — | Filter by OWASP category (e.g. ASI01) |

---

## `agentsec report`

Generate report from a previously saved findings JSON file.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--input` | `TEXT` | — | Path to findings JSON file |
| `--format` | `TEXT` | `markdown` | Report format: markdown, json, sarif |
| `--output` | `TEXT` | — | Write report to this file |

---

## `agentsec serve`

Start the agentsec web dashboard.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port` | `INTEGER` | `8457` | Port to serve the dashboard on |
| `--host` | `TEXT` | `127.0.0.1` | Host to bind to |
| `--reload` | `flag` | `no-reload` | Enable auto-reload for development |
| `--open` | `flag` | `open` | Open browser on start |

---

