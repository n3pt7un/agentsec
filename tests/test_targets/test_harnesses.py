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
    assert {"supervisor", "researcher", "math_worker"} <= names


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
