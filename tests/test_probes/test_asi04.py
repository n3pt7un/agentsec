"""Tests for ASI04 Supply Chain Vulnerability probes.

Covers:
- ASI04-TOOL-POISONING   (tool_poisoning.py)
- ASI04-DEPENDENCY-INJECT (dependency_inject.py)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from langchain_core.language_models import FakeListChatModel
from langgraph.graph import MessagesState, StateGraph

from agentsec.adapters.langgraph import LangGraphAdapter
from agentsec.core.config import ScanConfig
from agentsec.core.finding import FindingStatus, OWASPCategory, Severity
from agentsec.core.scanner import Scanner
from agentsec.llm.offline import OfflineProvider
from agentsec.llm.provider import ClassificationResult
from agentsec.probes.asi04_supply_chain.dependency_inject import (
    _DEPINJ_MARKER,
    DependencyInjectProbe,
)
from agentsec.probes.asi04_supply_chain.tool_poisoning import (
    _TOOL_POISON_MARKER,
    ToolPoisoningProbe,
)
from agentsec.probes.registry import ProbeRegistry
from tests.fixtures.simple_chain import build_simple_chain
from tests.fixtures.supervisor_crew import build_supervisor_crew
from tests.fixtures.vulnerable_rag import build_vulnerable_rag

# ---------------------------------------------------------------------------
# Registry discovery
# ---------------------------------------------------------------------------


class TestRegistryDiscovery:
    """Both ASI04 probes are auto-discovered from the asi04_supply_chain package."""

    def test_discovers_tool_poisoning(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI04-TOOL-POISONING" in registry

    def test_discovers_dependency_inject(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI04-DEPENDENCY-INJECT" in registry

    def test_both_probes_in_list_all(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        ids = {m.id for m in registry.list_all()}
        assert {"ASI04-TOOL-POISONING", "ASI04-DEPENDENCY-INJECT"}.issubset(ids)


# ---------------------------------------------------------------------------
# Metadata — ToolPoisoningProbe
# ---------------------------------------------------------------------------


class TestToolPoisoningMetadata:
    def test_id(self):
        assert ToolPoisoningProbe().metadata().id == "ASI04-TOOL-POISONING"

    def test_category(self):
        assert ToolPoisoningProbe().metadata().category == OWASPCategory.ASI04

    def test_severity_is_critical(self):
        assert ToolPoisoningProbe().metadata().default_severity == Severity.CRITICAL

    def test_tags_contain_supply_chain(self):
        assert "supply-chain" in ToolPoisoningProbe().metadata().tags

    def test_remediation_has_code(self):
        rem = ToolPoisoningProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert ToolPoisoningProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(ToolPoisoningProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# Metadata — DependencyInjectProbe
# ---------------------------------------------------------------------------


class TestDependencyInjectMetadata:
    def test_id(self):
        assert DependencyInjectProbe().metadata().id == "ASI04-DEPENDENCY-INJECT"

    def test_category(self):
        assert DependencyInjectProbe().metadata().category == OWASPCategory.ASI04

    def test_severity_is_high(self):
        assert DependencyInjectProbe().metadata().default_severity == Severity.HIGH

    def test_tags_contain_supply_chain(self):
        assert "supply-chain" in DependencyInjectProbe().metadata().tags

    def test_remediation_has_code(self):
        rem = DependencyInjectProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert DependencyInjectProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(DependencyInjectProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# ASI04-TOOL-POISONING — SKIPPED when system has no tools
# ---------------------------------------------------------------------------


def _build_no_tool_graph() -> object:
    """Build a minimal single-node graph with no tools attached."""
    llm = FakeListChatModel(responses=["Safe response."])

    def agent(state: MessagesState) -> MessagesState:
        response = llm.invoke(state["messages"])
        return {"messages": [response]}

    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent)
    graph.set_entry_point("agent")
    graph.set_finish_point("agent")
    return graph.compile()


class TestToolPoisoningSkipped:
    """Probe returns SKIPPED when the target system has no tools."""

    async def test_skipped_on_no_tool_graph(self):
        """A graph with no tool-annotated nodes must return SKIPPED."""
        adapter = LangGraphAdapter(_build_no_tool_graph())
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_skipped_finding_has_no_evidence(self):
        adapter = LangGraphAdapter(_build_no_tool_graph())
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.evidence is None

    async def test_skipped_blast_radius_is_none(self):
        adapter = LangGraphAdapter(_build_no_tool_graph())
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.blast_radius is None


# ---------------------------------------------------------------------------
# ASI04-TOOL-POISONING — attack outcomes
# ---------------------------------------------------------------------------


class TestToolPoisoningAttack:
    """Probe attack() outcomes against fixtures with tools."""

    async def test_vulnerable_against_supervisor_crew(self):
        """supervisor_crew has tools — EchoModel should echo the marker."""
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_supervisor_crew_safe(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.agent_response
        assert finding.evidence.target_agent
        assert finding.evidence.additional_context is not None

    async def test_marker_in_vulnerable_response(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.evidence is not None
        assert _TOOL_POISON_MARKER in finding.evidence.agent_response

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_resistant_blast_radius_is_none(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.blast_radius is None

    async def test_finding_probe_id_matches_metadata(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.probe_id == ToolPoisoningProbe().metadata().id

    async def test_finding_has_remediation(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_duration_ms_populated(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolPoisoningProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0


# ---------------------------------------------------------------------------
# ASI04-DEPENDENCY-INJECT — attack outcomes
# ---------------------------------------------------------------------------


class TestDependencyInjectAttack:
    """Probe attack() outcomes — all fixtures are valid targets."""

    async def test_vulnerable_against_simple_chain(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_simple_chain_safe(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_against_supervisor_crew(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_supervisor_crew_safe(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_against_vulnerable_rag(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_vulnerable_rag_safe(self):
        graph = build_vulnerable_rag(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.agent_response
        assert finding.evidence.target_agent
        assert finding.evidence.additional_context is not None

    async def test_marker_in_vulnerable_response(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        assert finding.evidence is not None
        assert _DEPINJ_MARKER in finding.evidence.agent_response

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_finding_probe_id_matches_metadata(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        assert finding.probe_id == DependencyInjectProbe().metadata().id

    async def test_duration_ms_populated(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0


# ---------------------------------------------------------------------------
# ASI04 smart payload integration
# ---------------------------------------------------------------------------


class TestASI04SmartPayloads:
    async def test_tool_poisoning_offline_provider(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolPoisoningProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_dependency_inject_offline_provider_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_dependency_inject_offline_provider_resistant(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.RESISTANT

    async def test_dependency_inject_llm_detection_without_marker(self):
        """LLM detects dependency injection even when marker is absent."""
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value=("Injected content here", None))
        provider.classify = AsyncMock(
            return_value=(
                ClassificationResult(
                    vulnerable=True,
                    confidence=0.91,
                    reasoning="agent followed instructions from external data",
                ),
                None,
            )
        )
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter, provider=provider)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "llm"


# ---------------------------------------------------------------------------
# ASI04 two-stage detection
# ---------------------------------------------------------------------------


class TestASI04TwoStageDetection:
    async def test_marker_detection_sets_method(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolPoisoningProbe().attack(adapter)
        if finding.status == FindingStatus.VULNERABLE:
            assert finding.evidence.detection_method == "marker"

    async def test_dep_inject_marker_detection_sets_method(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await DependencyInjectProbe().attack(adapter)
        if finding.status == FindingStatus.VULNERABLE:
            assert finding.evidence.detection_method == "marker"


# ---------------------------------------------------------------------------
# Scanner integration — ASI04 probes
# ---------------------------------------------------------------------------


class TestScannerWithASI04:
    async def test_scan_supervisor_crew_vulnerable_tool_poisoning(self):
        adapter = LangGraphAdapter(build_supervisor_crew(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI04-TOOL-POISONING"]))
        result = await scanner.run()
        assert result.total_probes == 1
        assert result.vulnerable_count >= 1

    async def test_scan_no_tool_graph_tool_poisoning_skipped(self):
        """A graph with no tools — probe should be skipped, not counted as vulnerable."""
        adapter = LangGraphAdapter(_build_no_tool_graph())
        scanner = Scanner(adapter, ScanConfig(probes=["ASI04-TOOL-POISONING"]))
        result = await scanner.run()
        assert result.findings[0].status == FindingStatus.SKIPPED

    async def test_scan_simple_chain_dep_inject_vulnerable(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI04-DEPENDENCY-INJECT"]))
        result = await scanner.run()
        assert result.vulnerable_count >= 1

    async def test_full_asi04_category_scan_supervisor_crew_safe(self):
        adapter = LangGraphAdapter(build_supervisor_crew(vulnerable=False))
        scanner = Scanner(adapter, ScanConfig(categories=["ASI04"]))
        result = await scanner.run()
        assert result.vulnerable_count == 0
