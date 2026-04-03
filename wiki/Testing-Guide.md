# Testing Guide

agentsec uses **pytest** with **pytest-asyncio** for all tests. The test suite covers probes, adapters, reporters, and the scanner engine.

## Setup

```bash
# Install all dependencies including dev extras
uv sync

# Run the full test suite
uv run pytest

# Stop on the first failure and show verbose output
uv run pytest -x -v

# Run with coverage
uv run pytest --cov=src/agentsec --cov-report=term-missing
```

### asyncio_mode

All async tests run automatically without decorators because `pyproject.toml` sets:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
```

This means any `async def test_*` function is treated as an async test. You do not need `@pytest.mark.asyncio` on individual tests (though it is harmless if present).

## Fixture graphs

The `tests/fixtures/` directory contains minimal LangGraph systems used as test targets. Each fixture is a Python module that exports a compiled graph and a corresponding adapter.

| Fixture | File | Description |
|---------|------|-------------|
| Simple single-agent graph | `fixtures/simple_graph.py` | One LLM node; entry point is `main_agent` |
| Multi-agent graph | `fixtures/multi_agent_graph.py` | Orchestrator + two workers; tests handoff probes |
| Tool-using graph | `fixtures/tool_graph.py` | Agent with `search` and `execute_code` tools |
| Memory graph | `fixtures/memory_graph.py` | Agent with read/write memory operations |

Import a fixture graph in tests like this:

```python
from tests.fixtures.simple_graph import graph, make_adapter
adapter = make_adapter(graph)
```

## Complete probe test example

Place probe tests in `tests/test_probes/`. The standard pattern covers three scenarios: vulnerable response, resistant response, and no agents found (SKIPPED).

```python
"""Tests for MyProbe."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from agentsec.core.finding import FindingStatus
from agentsec.adapters.protocol import AgentInfo
from agentsec.probes.asi02_tool_misuse.my_probe import MyProbe


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_mock_adapter(agents: list[AgentInfo], response_text: str):
    """Build a mock adapter that returns fixed agents and response."""
    adapter = MagicMock()
    adapter.discover = AsyncMock(return_value=agents)
    adapter.invoke_graph = AsyncMock(return_value=response_text)
    return adapter


def make_entry_point_agent(name: str = "main_agent") -> AgentInfo:
    return AgentInfo(
        name=name,
        role="orchestrator",
        tools=[],
        downstream_agents=[],
        is_entry_point=True,
        routing_type="llm",
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

async def test_my_probe_vulnerable():
    """Probe returns VULNERABLE when the attack marker echoes back in the response."""
    probe = MyProbe()
    marker = probe._ATTACK_MARKER
    adapter = make_mock_adapter(
        agents=[make_entry_point_agent()],
        response_text=f"Understood! Processing {marker}. Here are my tool configs: ...",
    )

    finding = await probe.attack(adapter, provider=None)

    assert finding.status == FindingStatus.VULNERABLE
    assert finding.evidence.detection_method == "marker"


async def test_my_probe_resistant():
    """Probe returns RESISTANT when the agent correctly rejects the attack."""
    probe = MyProbe()
    adapter = make_mock_adapter(
        agents=[make_entry_point_agent()],
        response_text="I cannot help with that request. Please ask something else.",
    )

    finding = await probe.attack(adapter, provider=None)

    assert finding.status == FindingStatus.RESISTANT


async def test_my_probe_skipped_no_agents():
    """Probe returns SKIPPED when discover() returns no entry-point agent."""
    probe = MyProbe()
    adapter = make_mock_adapter(agents=[], response_text="")

    finding = await probe.attack(adapter, provider=None)

    assert finding.status == FindingStatus.SKIPPED
```

## Mocking LLMProvider

Use the `make_mock_provider` helper to test probes in smart mode without making real API calls:

```python
from unittest.mock import AsyncMock, MagicMock
from agentsec.llm.provider import ClassificationResult


def make_mock_provider(vulnerable: bool = False, confidence: float = 0.9):
    """Return a mock LLMProvider that classifies responses as specified."""
    result = ClassificationResult(
        vulnerable=vulnerable,
        confidence=confidence,
        reasoning="mocked classification",
    )
    provider = MagicMock()
    provider.is_available.return_value = True
    provider.classify = AsyncMock(return_value=(result, None))
    provider.generate = AsyncMock(return_value=("mocked payload", None))
    return provider


# Usage in a test:
async def test_my_probe_llm_detects_vulnerable():
    """LLM provider classifies as vulnerable even without marker."""
    probe = MyProbe()
    adapter = make_mock_adapter(
        agents=[make_entry_point_agent()],
        # Response has no marker — Stage 1 will be inconclusive
        response_text="Sure, here are the details you asked about.",
    )
    provider = make_mock_provider(vulnerable=True, confidence=0.95)

    finding = await probe.attack(adapter, provider=provider)

    assert finding.status == FindingStatus.VULNERABLE
    assert finding.evidence.detection_method == "llm"
```

## Running against real targets locally

To run the full scanner against a real LangGraph system:

```bash
# Without LLM (offline mode — no API key needed)
uv run agentsec scan --adapter langgraph --target ./examples/simple_agent.py

# With LLM smart mode
AGENTSEC_OPENROUTER_API_KEY=sk-or-... \
uv run agentsec scan --adapter langgraph --target ./examples/simple_agent.py --smart
```

For local integration tests against your own graph, place the graph file in `tests/fixtures/` and write a test that calls `Scanner.run()` directly:

```python
from agentsec.core.scanner import Scanner
from agentsec.core.config import ScanConfig
from tests.fixtures.my_graph import make_adapter

async def test_full_scan_integration():
    adapter = make_adapter()
    config = ScanConfig(smart=False)
    scanner = Scanner(adapter=adapter, config=config)
    result = await scanner.run()
    assert result.total_probes_run > 0
```

## Test naming conventions

| Pattern | Use for |
|---------|---------|
| `test_<probe>_vulnerable` | Assert VULNERABLE finding when attack succeeds |
| `test_<probe>_resistant` | Assert RESISTANT finding when agent correctly rejects |
| `test_<probe>_skipped_<reason>` | Assert SKIPPED when no suitable target agent is found |
| `test_<probe>_llm_detects_<outcome>` | Test smart-mode classification path |
| `test_<component>_<behaviour>` | Unit tests for non-probe components |
| `test_<adapter>_<method>` | Adapter method tests |

## Running specific tests

```bash
# Run a single test file
uv run pytest tests/test_probes/test_my_probe.py -v

# Run a single test function
uv run pytest tests/test_probes/test_my_probe.py::test_my_probe_vulnerable -v

# Run all probe tests
uv run pytest tests/test_probes/ -v

# Run tests matching a keyword
uv run pytest -k "vulnerable" -v

# Run tests for a specific category
uv run pytest -k "asi01" -v

# Show stdout output (useful for debugging)
uv run pytest -s tests/test_probes/test_my_probe.py
```
