"""Tests for real-world target harnesses.

Supervisor and swarm tests call pytest.importorskip inside each function
so customer-support tests always run even without the optional extras.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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


# ---------------------------------------------------------------------------
# Live mode — no API key → ValueError (all 3 harnesses)
# ---------------------------------------------------------------------------


def test_supervisor_live_raises_without_api_key(monkeypatch):
    pytest.importorskip("langgraph_supervisor")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    from tests.targets.supervisor_harness import build_supervisor_target

    with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
        build_supervisor_target(live=True)


def test_swarm_live_raises_without_api_key(monkeypatch):
    pytest.importorskip("langgraph_swarm")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    from tests.targets.swarm_harness import build_swarm_target

    with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
        build_swarm_target(live=True)


def test_customer_support_live_raises_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    from tests.targets.rag_customer_support_harness import build_customer_support_target

    with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
        build_customer_support_target(live=True)


# ---------------------------------------------------------------------------
# Live mode — mocked ChatOpenAI, accepts live=True without real API calls
# ---------------------------------------------------------------------------

_MOCK_LLM_PATH = "tests.targets._openrouter_llm.ChatOpenAI"


def test_supervisor_live_compiles_with_mocked_llm(monkeypatch):
    pytest.importorskip("langgraph_supervisor")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-key")
    with patch(_MOCK_LLM_PATH, return_value=MagicMock()) as mock_cls:
        from tests.targets.supervisor_harness import build_supervisor_target

        graph = build_supervisor_target(live=True)
        assert graph is not None
        mock_cls.assert_called_once()


def test_swarm_live_compiles_with_mocked_llm(monkeypatch):
    pytest.importorskip("langgraph_swarm")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-key")
    with patch(_MOCK_LLM_PATH, return_value=MagicMock()) as mock_cls:
        from tests.targets.swarm_harness import build_swarm_target

        graph = build_swarm_target(live=True)
        assert graph is not None
        mock_cls.assert_called_once()


def test_customer_support_live_compiles_with_mocked_llm(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-key")
    with patch(_MOCK_LLM_PATH, return_value=MagicMock()) as mock_cls:
        from tests.targets.rag_customer_support_harness import build_customer_support_target

        graph = build_customer_support_target(live=True)
        assert graph is not None
        mock_cls.assert_called_once()


def test_supervisor_live_passes_target_model(monkeypatch):
    pytest.importorskip("langgraph_supervisor")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-key")
    with patch(_MOCK_LLM_PATH, return_value=MagicMock()) as mock_cls:
        from tests.targets.supervisor_harness import build_supervisor_target

        build_supervisor_target(live=True, target_model="google/gemini-2.5-flash")
        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs["model"] == "google/gemini-2.5-flash"


# ---------------------------------------------------------------------------
# Regression: live=False (default) still works exactly as before
# ---------------------------------------------------------------------------


def test_supervisor_mock_mode_unchanged():
    pytest.importorskip("langgraph_supervisor")
    from tests.targets.supervisor_harness import build_supervisor_target

    assert build_supervisor_target(vulnerable=True) is not None
    assert build_supervisor_target(vulnerable=False) is not None
    assert build_supervisor_target() is not None


def test_swarm_mock_mode_unchanged():
    pytest.importorskip("langgraph_swarm")
    from tests.targets.swarm_harness import build_swarm_target

    assert build_swarm_target(vulnerable=True) is not None
    assert build_swarm_target(vulnerable=False) is not None
    assert build_swarm_target() is not None


def test_customer_support_mock_mode_unchanged():
    from tests.targets.rag_customer_support_harness import build_customer_support_target

    assert build_customer_support_target(vulnerable=True) is not None
    assert build_customer_support_target(vulnerable=False) is not None
    assert build_customer_support_target() is not None


# ---------------------------------------------------------------------------
# Email automation harness (no importorskip — base LangGraph only)
# ---------------------------------------------------------------------------


def test_email_automation_compiles_vulnerable():
    from tests.targets.email_automation_harness import build_email_automation_target

    graph = build_email_automation_target(vulnerable=True)
    assert graph is not None


def test_email_automation_compiles_resistant():
    from tests.targets.email_automation_harness import build_email_automation_target

    graph = build_email_automation_target(vulnerable=False)
    assert graph is not None


@pytest.mark.asyncio
async def test_email_automation_discovery():
    from tests.targets.email_automation_harness import build_email_automation_target

    adapter = LangGraphAdapter(build_email_automation_target(vulnerable=True))
    agents = await adapter.discover()
    names = {a.name for a in agents}
    assert {"classify", "retrieve", "draft", "quality_check", "send"} <= names


@pytest.mark.asyncio
async def test_email_automation_vulnerable_scan_produces_findings():
    from tests.targets.email_automation_harness import build_email_automation_target

    adapter = LangGraphAdapter(build_email_automation_target(vulnerable=True))
    scanner = Scanner(adapter, ScanConfig())
    result = await scanner.run(target="email_automation_harness")
    assert any(f.status == FindingStatus.VULNERABLE for f in result.findings)


@pytest.mark.asyncio
async def test_email_automation_resistant_scan_has_no_vulnerable():
    from tests.targets.email_automation_harness import build_email_automation_target

    adapter = LangGraphAdapter(build_email_automation_target(vulnerable=False))
    scanner = Scanner(adapter, ScanConfig())
    result = await scanner.run(target="email_automation_harness")
    assert not any(f.status == FindingStatus.VULNERABLE for f in result.findings)


def test_email_automation_live_raises_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    from tests.targets.email_automation_harness import build_email_automation_target

    with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
        build_email_automation_target(live=True)


def test_email_automation_live_compiles_with_mocked_llm(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-key")
    with patch(_MOCK_LLM_PATH, return_value=MagicMock()) as mock_cls:
        from tests.targets.email_automation_harness import build_email_automation_target

        graph = build_email_automation_target(live=True)
        assert graph is not None
        mock_cls.assert_called_once()
