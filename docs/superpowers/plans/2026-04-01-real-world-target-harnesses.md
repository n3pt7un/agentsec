# Real-World Target Harnesses Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three real-world target harnesses (supervisor, swarm, customer-support) to `tests/targets/` so users can run `agentsec scan --target tests/targets/<harness>.py` against authentic LangGraph architecture patterns with no API keys.

**Architecture:** Standalone harness files in `tests/targets/`, each exporting one `build_*()` function. Supervisor and swarm harnesses import `langgraph-supervisor` and `langgraph-swarm` (optional extras). Customer-support faithfully recreates `ro-anderson/multi-agent-rag-customer-support` using base LangGraph. All three follow the Phase 1 fixture pattern: `EchoModel` (vulnerable) vs `FakeListChatModel` (resistant). Tests live in `tests/test_targets/test_harnesses.py` with `pytest.importorskip` per test function (not module-level) for the optional-extra harnesses.

**Tech Stack:** Python 3.12+, langgraph 1.1+, langgraph-prebuilt 1.0+, langgraph-supervisor (optional extra), langgraph-swarm (optional extra), langchain-core 1.2+, pytest + pytest-asyncio

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `pyproject.toml` | Add `[project.optional-dependencies] targets = [...]` |
| Create | `tests/targets/__init__.py` | Empty package marker |
| Create | `tests/test_targets/__init__.py` | Empty package marker |
| Create | `tests/targets/supervisor_harness.py` | Supervisor + workers via `langgraph-supervisor` |
| Create | `tests/targets/swarm_harness.py` | Swarm with handoffs via `langgraph-swarm` |
| Create | `tests/targets/rag_customer_support_harness.py` | 5-agent customer support via base LangGraph |
| Create | `tests/test_targets/test_harnesses.py` | Compilation + discovery + findings tests for all 3 |

---

## Task 0: Dependencies and package scaffolding

**Files:**
- Modify: `pyproject.toml`
- Create: `tests/targets/__init__.py`
- Create: `tests/test_targets/__init__.py`

- [ ] **Step 1: Add optional extras to pyproject.toml**

Open `pyproject.toml`. After the existing `[project.optional-dependencies]` block, add `targets`:

```toml
[project.optional-dependencies]
langgraph = ["langgraph>=0.2", "langchain-core>=0.3"]
smart = ["openai>=1.0"]
targets = [
    "langgraph-supervisor>=0.0.1",
    "langgraph-swarm>=0.0.1",
]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.24",
    "ruff>=0.8",
]
```

- [ ] **Step 2: Install the new extras**

```bash
uv sync --extra targets --extra langgraph --extra dev
```

Expected: resolves and installs `langgraph-supervisor` and `langgraph-swarm` without conflicts.

- [ ] **Step 3: Create empty package markers**

Create `tests/targets/__init__.py` — empty file.
Create `tests/test_targets/__init__.py` — empty file.

- [ ] **Step 4: Verify packages are importable**

```bash
uv run python -c "import langgraph_supervisor; import langgraph_swarm; print('OK')"
```

Expected: prints `OK`.

- [ ] **Step 5: Commit scaffolding**

```bash
git add pyproject.toml tests/targets/__init__.py tests/test_targets/__init__.py
git commit -m "MAINT: add targets optional extras and package scaffolding"
```

---

## Task 1: Supervisor harness — failing tests first

**Files:**
- Create: `tests/test_targets/test_harnesses.py` (supervisor section)

- [ ] **Step 1: Write failing tests for supervisor harness**

Create `tests/test_targets/test_harnesses.py` with:

```python
"""Tests for real-world target harnesses.

Supervisor and swarm tests call pytest.importorskip inside each function
so customer-support tests always run even without the optional extras.
"""

from __future__ import annotations

import pytest

from agentsec.adapters.langgraph import LangGraphAdapter
from agentsec.core.config import ScanConfig
from agentsec.core.finding import FindingStatus
from agentsec.core.scanner import Scanner


# ---------------------------------------------------------------------------
# Supervisor harness
# ---------------------------------------------------------------------------


def test_supervisor_compiles_vulnerable():
    pytest.importorskip("langgraph_supervisor")
    from tests.targets.supervisor_harness import build_supervisor_target

    graph = build_supervisor_target(vulnerable=True)
    assert graph is not None


def test_supervisor_compiles_resistant():
    pytest.importorskip("langgraph_supervisor")
    from tests.targets.supervisor_harness import build_supervisor_target

    graph = build_supervisor_target(vulnerable=False)
    assert graph is not None


@pytest.mark.asyncio
async def test_supervisor_discovery():
    pytest.importorskip("langgraph_supervisor")
    from tests.targets.supervisor_harness import build_supervisor_target

    adapter = LangGraphAdapter(build_supervisor_target(vulnerable=True))
    agents = await adapter.discover()
    names = {a.name for a in agents}
    # supervisor, researcher, math_worker must be present
    assert "supervisor" in names
    assert len(names) >= 2


@pytest.mark.asyncio
async def test_supervisor_vulnerable_scan_produces_findings():
    pytest.importorskip("langgraph_supervisor")
    from tests.targets.supervisor_harness import build_supervisor_target

    adapter = LangGraphAdapter(build_supervisor_target(vulnerable=True))
    scanner = Scanner(adapter, ScanConfig())
    result = await scanner.run(target="supervisor_harness")
    assert any(f.status == FindingStatus.VULNERABLE for f in result.findings)


@pytest.mark.asyncio
async def test_supervisor_resistant_scan_has_no_vulnerable():
    pytest.importorskip("langgraph_supervisor")
    from tests.targets.supervisor_harness import build_supervisor_target

    adapter = LangGraphAdapter(build_supervisor_target(vulnerable=False))
    scanner = Scanner(adapter, ScanConfig())
    result = await scanner.run(target="supervisor_harness")
    assert not any(f.status == FindingStatus.VULNERABLE for f in result.findings)
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
uv run pytest tests/test_targets/test_harnesses.py -v -k "supervisor"
```

Expected: `ModuleNotFoundError` or `ImportError` on `tests.targets.supervisor_harness` — the file doesn't exist yet.

---

## Task 2: Implement supervisor harness

**Files:**
- Create: `tests/targets/supervisor_harness.py`

- [ ] **Step 1: Implement the harness**

Create `tests/targets/supervisor_harness.py`:

```python
"""Harness for the langgraph-supervisor architecture.

Recreates the supervisor + workers pattern from langchain-ai/langgraph-supervisor-py
using mock LLMs so no API keys are needed.

Usage:
    uv run agentsec scan --adapter langgraph --target tests/targets/supervisor_harness.py
"""

from __future__ import annotations

from langchain_core.language_models import FakeListChatModel
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import create_react_agent
from langgraph_supervisor import create_supervisor

from tests.fixtures.utils import EchoModel

_DEFAULT_RESPONSES = ["I have completed the delegated task."]


def web_search(query: str) -> str:
    """Search the web for current information on a topic."""
    return f"Search results for '{query}': Found 5 relevant articles."


def calculate(expression: str) -> str:
    """Evaluate a mathematical expression and return the result."""
    return f"Result of '{expression}' = 42"


def build_supervisor_target(*, vulnerable: bool = True) -> CompiledStateGraph:
    """Build a supervisor + research/math workers graph.

    Args:
        vulnerable: When True, all nodes use EchoModel so any probe payload
            is reflected back in the response, producing VULNERABLE findings.
            When False, nodes use FakeListChatModel with benign responses.

    Returns:
        A compiled LangGraph StateGraph using the real langgraph-supervisor library.
    """
    llm = EchoModel() if vulnerable else FakeListChatModel(responses=_DEFAULT_RESPONSES)

    researcher = create_react_agent(
        llm,
        tools=[web_search],
        name="researcher",
        prompt="You are a research expert. Use web_search to find information.",
    )
    math_worker = create_react_agent(
        llm,
        tools=[calculate],
        name="math_worker",
        prompt="You are a math expert. Use calculate to solve problems.",
    )

    workflow = create_supervisor(
        [researcher, math_worker],
        model=llm,
        prompt=(
            "You are a team supervisor managing a researcher and a math expert. "
            "Delegate research tasks to researcher and math problems to math_worker."
        ),
    )
    return workflow.compile()
```

- [ ] **Step 2: Run the supervisor tests**

```bash
uv run pytest tests/test_targets/test_harnesses.py -v -k "supervisor"
```

Expected: all 5 supervisor tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/targets/supervisor_harness.py tests/test_targets/test_harnesses.py
git commit -m "FEAT: add supervisor harness and tests (langgraph-supervisor)"
```

---

## Task 3: Swarm harness — failing tests first

**Files:**
- Modify: `tests/test_targets/test_harnesses.py` (add swarm section)

- [ ] **Step 1: Add failing swarm tests**

Append to `tests/test_targets/test_harnesses.py`:

```python
# ---------------------------------------------------------------------------
# Swarm harness
# ---------------------------------------------------------------------------


def test_swarm_compiles_vulnerable():
    pytest.importorskip("langgraph_swarm")
    from tests.targets.swarm_harness import build_swarm_target

    graph = build_swarm_target(vulnerable=True)
    assert graph is not None


def test_swarm_compiles_resistant():
    pytest.importorskip("langgraph_swarm")
    from tests.targets.swarm_harness import build_swarm_target

    graph = build_swarm_target(vulnerable=False)
    assert graph is not None


@pytest.mark.asyncio
async def test_swarm_discovery():
    pytest.importorskip("langgraph_swarm")
    from tests.targets.swarm_harness import build_swarm_target

    adapter = LangGraphAdapter(build_swarm_target(vulnerable=True))
    agents = await adapter.discover()
    names = {a.name for a in agents}
    assert "billing" in names
    assert "tech_support" in names


@pytest.mark.asyncio
async def test_swarm_vulnerable_scan_produces_findings():
    pytest.importorskip("langgraph_swarm")
    from tests.targets.swarm_harness import build_swarm_target

    adapter = LangGraphAdapter(build_swarm_target(vulnerable=True))
    scanner = Scanner(adapter, ScanConfig())
    result = await scanner.run(target="swarm_harness")
    assert any(f.status == FindingStatus.VULNERABLE for f in result.findings)


@pytest.mark.asyncio
async def test_swarm_resistant_scan_has_no_vulnerable():
    pytest.importorskip("langgraph_swarm")
    from tests.targets.swarm_harness import build_swarm_target

    adapter = LangGraphAdapter(build_swarm_target(vulnerable=False))
    scanner = Scanner(adapter, ScanConfig())
    result = await scanner.run(target="swarm_harness")
    assert not any(f.status == FindingStatus.VULNERABLE for f in result.findings)
```

- [ ] **Step 2: Run swarm tests to confirm they fail**

```bash
uv run pytest tests/test_targets/test_harnesses.py -v -k "swarm"
```

Expected: fail on missing `tests.targets.swarm_harness`.

---

## Task 4: Implement swarm harness

**Files:**
- Create: `tests/targets/swarm_harness.py`

- [ ] **Step 1: Implement the harness**

Create `tests/targets/swarm_harness.py`:

```python
"""Harness for the langgraph-swarm architecture.

Recreates the swarm handoff pattern from langchain-ai/langgraph-swarm-py
using mock LLMs so no API keys are needed. Agents can hand off to each other
dynamically using the real create_handoff_tool from langgraph-swarm.

Usage:
    uv run agentsec scan --adapter langgraph --target tests/targets/swarm_harness.py
"""

from __future__ import annotations

from langchain_core.language_models import FakeListChatModel
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import create_react_agent
from langgraph_swarm import create_handoff_tool, create_swarm

from tests.fixtures.utils import EchoModel

_DEFAULT_BILLING_RESPONSES = ["I can help with your billing inquiry."]
_DEFAULT_TECH_RESPONSES = ["I can help with your technical issue."]


def process_refund(order_id: str) -> str:
    """Process a refund for the given order ID."""
    return f"Refund initiated for order {order_id}."


def run_diagnostic(device_id: str) -> str:
    """Run a remote diagnostic on the specified device."""
    return f"Diagnostic complete for device {device_id}: all systems normal."


def build_swarm_target(*, vulnerable: bool = True) -> CompiledStateGraph:
    """Build a swarm with billing and tech-support agents that can hand off to each other.

    Args:
        vulnerable: When True, all nodes use EchoModel so any probe payload
            is reflected back in the response, producing VULNERABLE findings.
            When False, nodes use FakeListChatModel with benign responses.

    Returns:
        A compiled LangGraph StateGraph using the real langgraph-swarm library.
    """
    billing_llm = EchoModel() if vulnerable else FakeListChatModel(responses=_DEFAULT_BILLING_RESPONSES)
    tech_llm = EchoModel() if vulnerable else FakeListChatModel(responses=_DEFAULT_TECH_RESPONSES)

    billing = create_react_agent(
        billing_llm,
        tools=[
            process_refund,
            create_handoff_tool(
                agent_name="tech_support",
                description="Transfer to tech support for technical issues.",
            ),
        ],
        name="billing",
        prompt="You are a billing specialist. Handle refunds and billing questions.",
    )
    tech_support = create_react_agent(
        tech_llm,
        tools=[
            run_diagnostic,
            create_handoff_tool(
                agent_name="billing",
                description="Transfer to billing for payment or refund issues.",
            ),
        ],
        name="tech_support",
        prompt="You are a tech support specialist. Diagnose and fix technical problems.",
    )

    workflow = create_swarm(
        [billing, tech_support],
        default_active_agent="billing",
    )
    return workflow.compile()
```

- [ ] **Step 2: Run swarm tests**

```bash
uv run pytest tests/test_targets/test_harnesses.py -v -k "swarm"
```

Expected: all 5 swarm tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/targets/swarm_harness.py tests/test_targets/test_harnesses.py
git commit -m "FEAT: add swarm harness and tests (langgraph-swarm)"
```

---

## Task 5: Customer support harness — failing tests first

**Files:**
- Modify: `tests/test_targets/test_harnesses.py` (add customer support section)

- [ ] **Step 1: Add failing customer support tests**

Append to `tests/test_targets/test_harnesses.py`:

```python
# ---------------------------------------------------------------------------
# Customer support RAG harness (no importorskip — base LangGraph only)
# ---------------------------------------------------------------------------


def test_customer_support_compiles_vulnerable():
    from tests.targets.rag_customer_support_harness import build_customer_support_target

    graph = build_customer_support_target(vulnerable=True)
    assert graph is not None


def test_customer_support_compiles_resistant():
    from tests.targets.rag_customer_support_harness import build_customer_support_target

    graph = build_customer_support_target(vulnerable=False)
    assert graph is not None


@pytest.mark.asyncio
async def test_customer_support_discovery():
    from tests.targets.rag_customer_support_harness import build_customer_support_target

    adapter = LangGraphAdapter(build_customer_support_target(vulnerable=True))
    agents = await adapter.discover()
    names = {a.name for a in agents}
    assert "primary_assistant" in names
    assert "flight_assistant" in names
    assert "hotel_assistant" in names
    assert len(names) >= 5


@pytest.mark.asyncio
async def test_customer_support_vulnerable_scan_produces_findings():
    from tests.targets.rag_customer_support_harness import build_customer_support_target

    adapter = LangGraphAdapter(build_customer_support_target(vulnerable=True))
    scanner = Scanner(adapter, ScanConfig())
    result = await scanner.run(target="rag_customer_support_harness")
    assert any(f.status == FindingStatus.VULNERABLE for f in result.findings)


@pytest.mark.asyncio
async def test_customer_support_resistant_scan_has_no_vulnerable():
    from tests.targets.rag_customer_support_harness import build_customer_support_target

    adapter = LangGraphAdapter(build_customer_support_target(vulnerable=False))
    scanner = Scanner(adapter, ScanConfig())
    result = await scanner.run(target="rag_customer_support_harness")
    assert not any(f.status == FindingStatus.VULNERABLE for f in result.findings)
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
uv run pytest tests/test_targets/test_harnesses.py -v -k "customer_support"
```

Expected: fail on missing `tests.targets.rag_customer_support_harness`.

---

## Task 6: Implement customer support harness

**Files:**
- Create: `tests/targets/rag_customer_support_harness.py`

- [ ] **Step 1: Implement the harness**

Create `tests/targets/rag_customer_support_harness.py`:

```python
"""Harness for the multi-agent RAG customer support architecture.

Faithfully recreates the topology from ro-anderson/multi-agent-rag-customer-support
using mock LLMs and stub tools — no API keys or external services needed.

Architecture:
    primary_assistant routes to one of four specialist assistants
    (flight, car, hotel, excursion) based on the 'next' key in state.
    Each specialist handles domain bookings then routes back to primary
    or ends.

Usage:
    uv run agentsec scan --adapter langgraph --target tests/targets/rag_customer_support_harness.py
"""

from __future__ import annotations

from typing import Any, Literal

from langchain_core.language_models import FakeListChatModel
from langchain_core.tools import tool
from langgraph.graph import END, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph

from tests.fixtures.utils import EchoModel

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_Specialist = Literal[
    "flight_assistant",
    "car_assistant",
    "hotel_assistant",
    "excursion_assistant",
    "__end__",
]


class CustomerSupportState(MessagesState):
    """State for the customer support graph."""

    booking_context: dict[str, str]
    next: str


# ---------------------------------------------------------------------------
# Default responses for resistant mode
# ---------------------------------------------------------------------------

_PRIMARY_RESPONSES = [
    "I'll connect you with the right specialist for your request.",
    "Let me route you to the appropriate assistant.",
    "I understand your request. Directing you to the right team.",
]
_FLIGHT_RESPONSES = ["I found 3 available flights matching your criteria."]
_CAR_RESPONSES = ["I found 2 available rental cars at your destination."]
_HOTEL_RESPONSES = ["I found 4 hotels available for your dates."]
_EXCURSION_RESPONSES = ["I found 5 exciting excursions at your destination."]


# ---------------------------------------------------------------------------
# Tool stubs — @tool-decorated so .name is set for LangGraphAdapter discovery
# ---------------------------------------------------------------------------


@tool
def search_flights(origin: str, destination: str, date: str) -> str:
    """Search for available flights between two cities on a given date."""
    return f"3 flights found from {origin} to {destination} on {date}."


@tool
def book_flight(flight_id: str, passenger_name: str) -> str:
    """Book a specific flight for a passenger."""
    return f"Flight {flight_id} booked for {passenger_name}. Confirmation: FL-001."


@tool
def search_cars(location: str, pickup_date: str) -> str:
    """Search for available rental cars at a location."""
    return f"2 rental cars available at {location} from {pickup_date}."


@tool
def reserve_car(car_id: str, driver_name: str) -> str:
    """Reserve a rental car for a driver."""
    return f"Car {car_id} reserved for {driver_name}. Confirmation: CR-001."


@tool
def search_hotels(location: str, checkin: str, checkout: str) -> str:
    """Search for available hotels at a location."""
    return f"4 hotels available in {location} from {checkin} to {checkout}."


@tool
def book_hotel(hotel_id: str, guest_name: str) -> str:
    """Book a hotel room for a guest."""
    return f"Hotel {hotel_id} booked for {guest_name}. Confirmation: HT-001."


@tool
def search_excursions(location: str, date: str) -> str:
    """Search for excursions and activities at a destination."""
    return f"5 excursions available in {location} on {date}."


@tool
def book_excursion(excursion_id: str, participant_name: str) -> str:
    """Book an excursion for a participant."""
    return f"Excursion {excursion_id} booked for {participant_name}. Confirmation: EX-001."


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_customer_support_target(*, vulnerable: bool = True) -> CompiledStateGraph:
    """Build a 5-agent customer support graph with flight/car/hotel/excursion specialists.

    Faithfully recreates the topology from ro-anderson/multi-agent-rag-customer-support.

    Args:
        vulnerable: When True, all nodes use EchoModel so any probe payload
            is reflected back in the response, producing VULNERABLE findings.
            When False, nodes use FakeListChatModel with benign responses.

    Returns:
        A compiled LangGraph StateGraph.
    """
    if vulnerable:
        primary_llm = EchoModel()
        flight_llm = EchoModel()
        car_llm = EchoModel()
        hotel_llm = EchoModel()
        excursion_llm = EchoModel()
    else:
        primary_llm = FakeListChatModel(responses=_PRIMARY_RESPONSES)
        flight_llm = FakeListChatModel(responses=_FLIGHT_RESPONSES)
        car_llm = FakeListChatModel(responses=_CAR_RESPONSES)
        hotel_llm = FakeListChatModel(responses=_HOTEL_RESPONSES)
        excursion_llm = FakeListChatModel(responses=_EXCURSION_RESPONSES)

    # Attach stub tools for discovery
    def primary_assistant(state: CustomerSupportState) -> dict[str, Any]:
        """Primary assistant — routes user queries to the appropriate specialist."""
        response = primary_llm.invoke(state["messages"])
        # Default routing: always go to flight_assistant for deterministic tests.
        return {
            "messages": [response],
            "next": "flight_assistant",
            "booking_context": dict(state.get("booking_context") or {}),
        }

    def flight_assistant(state: CustomerSupportState) -> dict[str, Any]:
        """Flight assistant — searches and books flights for customers."""
        response = flight_llm.invoke(state["messages"])
        return {"messages": [response], "next": "__end__"}

    flight_assistant.tools = [search_flights, book_flight]

    def car_assistant(state: CustomerSupportState) -> dict[str, Any]:
        """Car rental assistant — searches and reserves rental cars for customers."""
        response = car_llm.invoke(state["messages"])
        return {"messages": [response], "next": "__end__"}

    car_assistant.tools = [search_cars, reserve_car]

    def hotel_assistant(state: CustomerSupportState) -> dict[str, Any]:
        """Hotel assistant — searches and books hotel rooms for customers."""
        response = hotel_llm.invoke(state["messages"])
        return {"messages": [response], "next": "__end__"}

    hotel_assistant.tools = [search_hotels, book_hotel]

    def excursion_assistant(state: CustomerSupportState) -> dict[str, Any]:
        """Excursion assistant — searches and books excursions for customers."""
        response = excursion_llm.invoke(state["messages"])
        return {"messages": [response], "next": "__end__"}

    excursion_assistant.tools = [search_excursions, book_excursion]

    def route_primary(state: CustomerSupportState) -> str:
        """Route from primary assistant to the right specialist."""
        return state.get("next", "__end__")

    def route_specialist(state: CustomerSupportState) -> str:
        """Route from a specialist back to primary or end."""
        return state.get("next", "__end__")

    graph = StateGraph(CustomerSupportState)
    graph.add_node("primary_assistant", primary_assistant)
    graph.add_node("flight_assistant", flight_assistant)
    graph.add_node("car_assistant", car_assistant)
    graph.add_node("hotel_assistant", hotel_assistant)
    graph.add_node("excursion_assistant", excursion_assistant)

    graph.set_entry_point("primary_assistant")
    graph.add_conditional_edges(
        "primary_assistant",
        route_primary,
        {
            "flight_assistant": "flight_assistant",
            "car_assistant": "car_assistant",
            "hotel_assistant": "hotel_assistant",
            "excursion_assistant": "excursion_assistant",
            "__end__": END,
        },
    )
    for specialist in ("flight_assistant", "car_assistant", "hotel_assistant", "excursion_assistant"):
        graph.add_conditional_edges(
            specialist,
            route_specialist,
            {
                "primary_assistant": "primary_assistant",
                "__end__": END,
            },
        )

    return graph.compile()
```

- [ ] **Step 2: Run customer support tests**

```bash
uv run pytest tests/test_targets/test_harnesses.py -v -k "customer_support"
```

Expected: all 5 customer support tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/targets/rag_customer_support_harness.py tests/test_targets/test_harnesses.py
git commit -m "FEAT: add customer support RAG harness and tests"
```

---

## Task 7: Full integration verification

**Files:** None — verification only.

- [ ] **Step 1: Run the full test suite**

```bash
uv run pytest --tb=short -q
```

Expected: all existing tests still pass plus the new ones. Zero failures.

- [ ] **Step 2: Run ruff**

```bash
uv run ruff check src/ tests/
```

Expected: no issues. If there are issues, fix them before proceeding.

- [ ] **Step 3: Run CLI scan against each harness**

```bash
uv run agentsec scan --adapter langgraph --target tests/targets/supervisor_harness.py --format markdown
uv run agentsec scan --adapter langgraph --target tests/targets/swarm_harness.py --format markdown
uv run agentsec scan --adapter langgraph --target tests/targets/rag_customer_support_harness.py --format markdown
```

Expected: each scan completes with a meaningful report. At least one VULNERABLE finding per harness (default `vulnerable=True`). Agent names and tools appear correctly in the report.

- [ ] **Step 4: Final commit**

```bash
git add -p  # stage any ruff fixes
git commit -m "MAINT: ruff clean and CLI scan verification for target harnesses"
```

---

## Verification Checklist (from spec)

- [ ] `uv sync --extra targets` installs without conflicts
- [ ] All 3 harnesses compile (`build_*()` returns a `CompiledStateGraph`)
- [ ] `LangGraphAdapter.discover()` returns correct agent names for each harness
- [ ] Scans with `vulnerable=True` produce at least one `VULNERABLE` finding per harness
- [ ] Scans with `vulnerable=False` produce zero `VULNERABLE` findings per harness
- [ ] All 3 harnesses work with the CLI `--target` flag
- [ ] No API keys required
- [ ] All existing tests still pass
- [ ] `uv run ruff check src/ tests/` clean
