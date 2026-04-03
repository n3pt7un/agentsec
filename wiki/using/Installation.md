# Installation

## Requirements

- Python 3.12 or newer
- pip or [uv](https://docs.astral.sh/uv/) (recommended)

## Install

```bash
pip install agentsec-framework
```

Or with uv:

```bash
uv add agentsec-framework
```

## Optional extras

```bash
# Smart mode — LLM-powered payloads via OpenRouter
pip install "agentsec-framework[smart]"

# Real-world target harnesses (6 bundled LangGraph systems)
pip install "agentsec-framework[targets]"

# Web dashboard
pip install "agentsec-framework[dashboard]"

# Everything
pip install "agentsec-framework[smart,targets,dashboard]"
```

With uv:

```bash
uv sync --extra smart --extra targets --extra dashboard
```

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENTSEC_OPENROUTER_API_KEY` | Smart mode only | Your [OpenRouter](https://openrouter.ai/keys) API key |
| `AGENTSEC_VERBOSE` | No | Set `true` to print each finding as it completes |
| `AGENTSEC_TIMEOUT_PER_PROBE` | No | Max seconds per probe (default: 120) |

Variables can also be placed in a `.env` file in your project root — agentsec reads it automatically.

## Verify

```bash
agentsec --version
agentsec probes list
```

Expected output of `probes list`: a table of 20 probe IDs across ASI01–ASI10.
