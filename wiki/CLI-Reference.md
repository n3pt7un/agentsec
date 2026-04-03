# CLI Reference

## `agentsec scan`

Scan a multi-agent system for OWASP Agentic vulnerabilities.

```bash
agentsec scan --adapter langgraph --target ./my_agent.py [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--adapter` | str | `langgraph` | Adapter to use |
| `--target` | str | *(required)* | Path to target agent system or harness name |
| `--categories` | str | None | Comma-separated OWASP categories (e.g. `ASI01,ASI03`) |
| `--probes` | str | None | Comma-separated probe IDs |
| `--output` | str | None | Write report to this file (default: stdout) |
| `--format` | str | `markdown` | Report format: `markdown`, `json`, `sarif` |
| `--verbose` | bool | False | Print each finding as it completes |
| `--vulnerable` | bool | True | Pass `vulnerable=True` to fixture/harness builders |
| `--smart` | bool | False | Enable LLM-powered payloads via OpenRouter |
| `--model` | str | `anthropic/claude-sonnet-4.6` | OpenRouter model for smart mode |
| `--live` | bool | False | Use a real LLM for target agents (not mock) |
| `--target-model` | str | None | OpenRouter model ID for target agents (live mode) |
| `--detection-mode` | str | `marker_then_llm` | Detection strategy: `marker_then_llm` or `llm_only` |

**Exit codes:**
- `0` — scan completed (findings may include VULNERABLE)
- `1` — error (bad arguments, LLM auth failure, target load failure)

**Environment variable overrides:**

Any `ScanConfig` field can be set via `AGENTSEC_<FIELD>` environment variable:

```bash
export AGENTSEC_OPENROUTER_API_KEY=sk-or-...
export AGENTSEC_VERBOSE=true
export AGENTSEC_TIMEOUT_PER_PROBE=60
```

---

## `agentsec probe`

Run a single probe for debugging.

```bash
agentsec probe ASI01-INDIRECT-INJECT --target ./my_agent.py [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--adapter` | str | `langgraph` | Adapter to use |
| `--target` | str | *(required)* | Path to target |
| `--vulnerable` | bool | True | Vulnerable flag for fixture builders |
| `--smart` | bool | False | Smart mode |
| `--model` | str | `anthropic/claude-sonnet-4.6` | OpenRouter model |
| `--live` | bool | False | Live LLM for target agents |
| `--target-model` | str | None | Model for target agents |

Prints full finding detail: attack payload, agent response, blast radius, remediation.

---

## `agentsec probes list`

List available probes.

```bash
agentsec probes list [--category ASI01]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--category` | str | None | Filter by OWASP category |

---

## `agentsec report`

Generate a report from a previously saved findings JSON file.

```bash
agentsec report --input findings.json --format sarif --output results.sarif
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--input` | str | *(required)* | Path to findings JSON file |
| `--format` | str | `markdown` | Output format: `markdown`, `json`, `sarif` |
| `--output` | str | None | Write to file (default: stdout) |

---

## `agentsec serve`

Start the agentsec web dashboard.

```bash
agentsec serve [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port` | int | `8457` | Port to listen on |
| `--host` | str | `127.0.0.1` | Host to bind to |
| `--reload` | bool | False | Auto-reload on code changes (dev only) |
| `--open/--no-open` | bool | `--open` | Open browser automatically |

Requires the `[dashboard]` extra: `pip install "agentsec-framework[dashboard]"`
