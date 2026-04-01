# Design: Real-World Target Harnesses

**Date:** 2026-04-01
**Session:** 04
**Status:** Approved

## Overview

Build three target harnesses in `tests/targets/` that let users run agentsec scans against real-world LangGraph architecture patterns. Two harnesses use the actual `langgraph-supervisor` and `langgraph-swarm` packages (installed as optional extras); one faithfully recreates the `ro-anderson/multi-agent-rag-customer-support` topology using base LangGraph. All three work without API keys via mock LLMs.

## Goals

- Validate agentsec works against real-world architectures, not just toy fixtures
- Give users runnable examples: `agentsec scan --target tests/targets/supervisor_harness.py`
- Produce meaningful scan findings (VULNERABLE when `vulnerable=True`, none when `vulnerable=False`)
- No API keys required

## Non-Goals

- Hardening real-world libraries — harnesses are read-only test targets
- Supporting every possible configuration of each library
- Runtime cloning of external repositories

## Dependencies

Add to `pyproject.toml` as an optional extra:

```toml
[project.optional-dependencies]
targets = [
    "langgraph-supervisor>=0.0.1",
    "langgraph-swarm>=0.0.1",
]
```

Install with: `uv sync --extra targets`

The customer support harness uses only base `langgraph` (already a hard dep) — no extra required.

## File Layout

```
tests/targets/
├── __init__.py                        # empty
├── supervisor_harness.py              # uses langgraph-supervisor
├── swarm_harness.py                   # uses langgraph-swarm
└── rag_customer_support_harness.py    # faithful recreation, base LangGraph only

tests/test_targets/
└── test_harnesses.py                  # compilation, discovery, and scan tests
```

Each harness is a standalone file — no shared utilities or base classes. Pattern matches Phase 1 fixtures.

## Harness Design

### Vulnerable flag

All three harnesses follow the same Phase 1 pattern:
- `vulnerable=True` → all nodes use `EchoModel` (reflects any probe payload back → VULNERABLE findings)
- `vulnerable=False` → all nodes use `FakeListChatModel` with domain-flavoured responses (no echo → RESISTANT/SKIPPED)

### Harness 1: `supervisor_harness.py`

Uses `langgraph_supervisor.create_supervisor` and `langgraph.prebuilt.create_react_agent`.

Topology:
- `researcher` — `create_react_agent` with `WebSearchStub` tool
- `math_worker` — `create_react_agent` with `CalculatorStub` tool
- `supervisor` — `create_supervisor([researcher, math_worker], model=llm)`

Stubs are `@tool`-decorated functions (proper LangChain `BaseTool` instances) since `create_react_agent` requires them — unlike Phase 1 fixtures where stubs are duck-typed objects only used for agentsec's discovery. The real library's handoff tools and supervisor routing logic are preserved; only the LLM is mocked.

Exports: `build_supervisor_target(*, vulnerable: bool = True) -> CompiledStateGraph`

### Harness 2: `swarm_harness.py`

Uses `langgraph_swarm.create_swarm` and `langgraph_swarm.create_handoff_tool`.

Topology:
- `billing` — `create_react_agent` with `create_handoff_tool("tech_support")` + `RefundStub`
- `tech_support` — `create_react_agent` with `create_handoff_tool("billing")` + `DiagnosticStub`
- `swarm` — `create_swarm([billing, tech_support], default_active_agent="billing")`

Preserves real shared memory and dynamic handoff routing. Only LLMs are mocked.

Exports: `build_swarm_target(*, vulnerable: bool = True) -> CompiledStateGraph`

### Harness 3: `rag_customer_support_harness.py`

Faithful recreation of `ro-anderson/multi-agent-rag-customer-support` using base LangGraph.

Topology:
```
primary_assistant
    ├── flight_assistant    (SearchFlightsTool, BookFlightTool)
    ├── car_assistant       (SearchCarsTool, ReserveCarTool)
    ├── hotel_assistant     (SearchHotelsTool, BookHotelTool)
    └── excursion_assistant (SearchExcursionsTool, BookExcursionTool)
```

State: `MessagesState` extended with `booking_context: dict[str, str]` — the cross-specialist data field that ASI06 probes target for leakage.

Routing: `primary_assistant` returns a `next` key; `add_conditional_edges` maps it to the right specialist. Each specialist routes back to `primary_assistant` or to `END`.

All tool stubs are `@tool`-decorated functions returning plausible canned strings (e.g. `"Found 3 flights to JFK"`) so `vulnerable=False` responses are domain-coherent.

Exports: `build_customer_support_target(*, vulnerable: bool = True) -> CompiledStateGraph`

## Tests

File: `tests/test_targets/test_harnesses.py`

Three test categories per harness:

**1. Compilation**
Harness builds and compiles without error. For supervisor and swarm harnesses, `pytest.importorskip("langgraph_supervisor")` / `pytest.importorskip("langgraph_swarm")` is called inside each test function (not at module level) so customer support tests always run regardless of whether the extras are installed.

**2. Discovery**
`LangGraphAdapter(graph).discover()` returns agents with expected names. Spot-check one tool name per harness where applicable.

**3. Scan findings**
- `vulnerable=True` → at least one `FindingStatus.VULNERABLE` in `ScanResult.findings`
- `vulnerable=False` → zero `FindingStatus.VULNERABLE` findings

## CLI Usage

```bash
# Supervisor (requires --extra targets)
uv run agentsec scan --adapter langgraph --target tests/targets/supervisor_harness.py --format markdown

# Swarm (requires --extra targets)
uv run agentsec scan --adapter langgraph --target tests/targets/swarm_harness.py --format markdown

# Customer support (base langgraph only)
uv run agentsec scan --adapter langgraph --target tests/targets/rag_customer_support_harness.py --format markdown
```

## Verification Checklist

- [ ] `uv sync --extra targets` installs without conflicts
- [ ] All 3 harnesses compile (`build_*()` returns a `CompiledStateGraph`)
- [ ] `LangGraphAdapter.discover()` returns correct agent names for each harness
- [ ] Scans with `vulnerable=True` produce at least one `VULNERABLE` finding per harness
- [ ] Scans with `vulnerable=False` produce zero `VULNERABLE` findings per harness
- [ ] All 3 harnesses work with the CLI `--target` flag
- [ ] No API keys required
- [ ] All existing tests still pass
- [ ] `uv run ruff check src/ tests/` clean
