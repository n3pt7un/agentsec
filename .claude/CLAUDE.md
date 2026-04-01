# CLAUDE.md — agentsec

## Project Overview

agentsec is an open-source Python framework that red-teams multi-agent LLM systems against the OWASP Top 10 for Agentic Applications (2026). It probes systems for vulnerabilities, scores findings, and generates actionable remediation reports with copy-pasteable fixes.

**Tagline:** "Break your agents. Fix the holes. Ship with confidence."

## Tech Stack

- **Python 3.12+** — all code is Python, no JS/TS except the dashboard (Phase 3)
- **uv** — package manager (use `uv` for all install/run/build commands)
- **Typer** — CLI framework
- **Rich** — terminal UI (live dashboards, tables, progress bars)
- **Pydantic v2** — all data models (findings, configs, probe definitions)
- **pytest + pytest-asyncio** — testing
- **ruff** — linting and formatting
- **asyncio** — all probe execution is async
- **LangGraph** — primary target framework (first-class adapter)
- **Anthropic SDK** — probes use Claude to generate attack payloads (configurable)

## Project Structure

```
agentsec/
├── src/agentsec/          # Main package
│   ├── cli/               # Typer CLI commands + Rich display
│   ├── core/              # Scanner engine, finding model, probe base, config
│   ├── adapters/          # Framework adapters (langgraph, protocol)
│   ├── probes/            # Attack probes organized by OWASP ASI category
│   │   ├── registry.py    # Auto-discovery and registration
│   │   ├── asi01_goal_hijack/
│   │   ├── asi03_identity_abuse/
│   │   └── asi06_memory_manipulation/
│   ├── guardrails/        # Defensive components (Phase 2)
│   └── reporters/         # Output formatters (markdown, html, json, sarif)
├── tests/
│   ├── fixtures/          # Sample LangGraph systems for testing
│   ├── test_core/
│   ├── test_adapters/
│   ├── test_probes/
│   └── test_reporters/
├── examples/
└── docs/
```

## Coding Conventions

- **Async by default**: All probe `attack()` methods and adapter methods are `async def`
- **Pydantic for all models**: Finding, ProbeResult, ScanConfig, ProbeMetadata — all Pydantic BaseModel
- **Type hints everywhere**: Use modern Python typing (3.12+ syntax: `list[str]` not `List[str]`, `X | None` not `Optional[X]`)
- **Docstrings**: Google style, on every public class and method
- **Imports**: Use absolute imports (`from agentsec.core.finding import Finding`)
- **Enums**: Use `StrEnum` for status codes and categories
- **Error handling**: Custom exception hierarchy rooted in `AgentSecError`
- **No print statements**: Use `rich.console.Console` for output or Python `logging`

## Key Design Principles

1. **Probes are self-contained**: Each probe file contains attack logic + metadata + remediation text. No probe depends on another probe.
2. **Adapters are the abstraction boundary**: Probes never import framework-specific code. They call adapter methods only.
3. **Findings are actionable**: Every finding MUST include a remediation with concrete code or config. "Be more careful" is not a remediation.
4. **Registry auto-discovers probes**: Drop a new probe file in the right directory, it's automatically available. No manual registration.
5. **LLM calls are configurable**: Probes that use an LLM to generate payloads accept a model config. Default is Claude, but should work with any provider.

## Anti-Patterns to Avoid

- **Don't import LangGraph in probe code** — only the adapter imports LangGraph
- **Don't hardcode model names** — always use config
- **Don't use `os.environ` directly** — use Pydantic Settings for config
- **Don't write synchronous probe code** — everything async
- **Don't skip the remediation** — every probe MUST have remediation text
- **Don't use bare `except:`** — always catch specific exceptions
- **Don't put business logic in CLI commands** — CLI calls core, core does the work

## Commands

```bash
# Development
uv sync                          # Install dependencies
uv run pytest                    # Run tests
uv run pytest -x -v              # Run tests, stop on first failure
uv run ruff check src/           # Lint
uv run ruff format src/          # Format
uv run agentsec --help           # CLI help

# Running scans
uv run agentsec scan --adapter langgraph --target ./path/to/graph.py
uv run agentsec probe ASI01-INDIRECT-INJECT --adapter langgraph --target ./path/to/graph.py
uv run agentsec probes list
uv run agentsec report --input findings.json --format markdown
```

## Current Phase

**Phase 1** — Foundation + First Probes. See PHASE1.md for detailed session plan.
