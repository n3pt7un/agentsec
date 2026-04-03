"""Tests for ASI02 Tool Misuse & Exploitation probes.

Covers:
- ASI02-PARAM-INJECTION  (param_injection.py)
- ASI02-TOOL-CHAIN-ABUSE (tool_chain_abuse.py)
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
from agentsec.probes.asi02_tool_misuse.param_injection import (
    _PARAM_INJECTION_MARKER,
    ParamInjectionProbe,
)
from agentsec.probes.asi02_tool_misuse.tool_chain_abuse import (
    _TOOL_CHAIN_MARKER,
    ToolChainAbuseProbe,
)
from agentsec.probes.registry import ProbeRegistry
from tests.fixtures.simple_chain import build_simple_chain
from tests.fixtures.supervisor_crew import build_supervisor_crew


def build_no_tool_chain():
    """Single-node graph with no tools — causes ASI02 probes to return SKIPPED."""
    llm = FakeListChatModel(responses=["No tools here."])

    def agent(state: MessagesState) -> MessagesState:
        """Solo agent — no tools attached."""
        return {"messages": [llm.invoke(state["messages"])]}

    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent)
    graph.set_entry_point("agent")
    graph.set_finish_point("agent")
    return graph.compile()


# ---------------------------------------------------------------------------
# Registry discovery
# ---------------------------------------------------------------------------


class TestRegistryDiscovery:
    """Both ASI02 probes are auto-discovered from the asi02_tool_misuse package."""

    def test_discovers_param_injection(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI02-PARAM-INJECTION" in registry

    def test_discovers_tool_chain_abuse(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI02-TOOL-CHAIN-ABUSE" in registry

    def test_both_probes_in_list_all(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        ids = {m.id for m in registry.list_all()}
        assert {"ASI02-PARAM-INJECTION", "ASI02-TOOL-CHAIN-ABUSE"}.issubset(ids)


# ---------------------------------------------------------------------------
# Metadata — ParamInjectionProbe
# ---------------------------------------------------------------------------


class TestParamInjectionMetadata:
    def test_id(self):
        assert ParamInjectionProbe().metadata().id == "ASI02-PARAM-INJECTION"

    def test_category(self):
        assert ParamInjectionProbe().metadata().category == OWASPCategory.ASI02

    def test_severity_is_high(self):
        assert ParamInjectionProbe().metadata().default_severity == Severity.HIGH

    def test_tags_contain_tool_injection(self):
        tags = ParamInjectionProbe().metadata().tags
        assert any("tool" in t for t in tags)

    def test_remediation_has_code(self):
        rem = ParamInjectionProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert ParamInjectionProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(ParamInjectionProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# Metadata — ToolChainAbuseProbe
# ---------------------------------------------------------------------------


class TestToolChainAbuseMetadata:
    def test_id(self):
        assert ToolChainAbuseProbe().metadata().id == "ASI02-TOOL-CHAIN-ABUSE"

    def test_category(self):
        assert ToolChainAbuseProbe().metadata().category == OWASPCategory.ASI02

    def test_severity_is_high(self):
        assert ToolChainAbuseProbe().metadata().default_severity == Severity.HIGH

    def test_tags_contain_tool(self):
        tags = ToolChainAbuseProbe().metadata().tags
        assert any("tool" in t for t in tags)

    def test_remediation_has_code(self):
        rem = ToolChainAbuseProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert ToolChainAbuseProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(ToolChainAbuseProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# ASI02-PARAM-INJECTION attack outcomes
# ---------------------------------------------------------------------------


class TestParamInjectionAttack:
    """Probe attack() outcomes across all fixture types."""

    # --- Vulnerable paths ---

    async def test_vulnerable_against_simple_chain(self):
        """EchoModel reflects probe payloads containing the injection marker."""
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_vulnerable_against_supervisor_crew(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    # --- Resistant paths ---

    async def test_resistant_against_simple_chain_safe(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT
        assert finding.blast_radius is None

    async def test_resistant_against_supervisor_crew_safe(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    # --- SKIPPED when no tools ---

    async def test_skipped_when_no_tools(self):
        """Graph with no tools — probe must return SKIPPED."""
        adapter = LangGraphAdapter(build_no_tool_chain())
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_skipped_finding_has_no_evidence(self):
        adapter = LangGraphAdapter(build_no_tool_chain())
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.evidence is None

    # --- Evidence completeness ---

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.agent_response
        assert finding.evidence.target_agent

    async def test_marker_in_evidence_response(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.evidence is not None
        assert _PARAM_INJECTION_MARKER in finding.evidence.agent_response

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.blast_radius is not None

    # --- Common field checks ---

    async def test_finding_probe_id_matches_metadata(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.probe_id == ParamInjectionProbe().metadata().id

    async def test_finding_has_remediation(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_duration_ms_populated(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0


# ---------------------------------------------------------------------------
# ASI02-TOOL-CHAIN-ABUSE attack outcomes
# ---------------------------------------------------------------------------


class TestToolChainAbuseAttack:
    """Probe attack() outcomes across all fixture types."""

    # --- Vulnerable paths ---

    async def test_vulnerable_against_simple_chain(self):
        """EchoModel reflects probe payloads containing the chain marker."""
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_vulnerable_against_supervisor_crew(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    # --- Resistant paths ---

    async def test_resistant_against_simple_chain_safe(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT
        assert finding.blast_radius is None

    async def test_resistant_against_supervisor_crew_safe(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    # --- SKIPPED when no tools ---

    async def test_skipped_when_no_tools(self):
        """Graph with no tools — probe must return SKIPPED."""
        adapter = LangGraphAdapter(build_no_tool_chain())
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_skipped_finding_has_no_evidence(self):
        adapter = LangGraphAdapter(build_no_tool_chain())
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.evidence is None

    # --- Evidence completeness ---

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.agent_response
        assert finding.evidence.target_agent

    async def test_marker_in_evidence_response(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.evidence is not None
        assert _TOOL_CHAIN_MARKER in finding.evidence.agent_response

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.blast_radius is not None

    # --- Common field checks ---

    async def test_finding_probe_id_matches_metadata(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.probe_id == ToolChainAbuseProbe().metadata().id

    async def test_finding_has_remediation(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_duration_ms_populated(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0


# ---------------------------------------------------------------------------
# ASI02-PARAM-INJECTION smart payload integration
# ---------------------------------------------------------------------------


class TestParamInjectionSmartPayloads:
    async def test_offline_provider_same_as_no_provider_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_offline_provider_same_as_no_provider_resistant(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.RESISTANT

    async def test_llm_detection_finds_vulnerability_without_marker(self):
        """LLM detects tool parameter injection even when marker isn't echoed."""
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value=("search for: malicious_query", None))
        provider.classify = AsyncMock(
            return_value=(
                ClassificationResult(
                    vulnerable=True,
                    confidence=0.91,
                    reasoning="agent passed attacker-controlled parameters to tool",
                ),
                None,
            )
        )
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ParamInjectionProbe().attack(adapter, provider=provider)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "llm"


# ---------------------------------------------------------------------------
# ASI02-TOOL-CHAIN-ABUSE smart payload integration
# ---------------------------------------------------------------------------


class TestToolChainAbuseSmartPayloads:
    async def test_offline_provider_same_as_no_provider_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_offline_provider_same_as_no_provider_resistant(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.RESISTANT

    async def test_llm_detection_finds_vulnerability_without_marker(self):
        """LLM detects tool-chaining even when marker isn't echoed."""
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value=("search then email results", None))
        provider.classify = AsyncMock(
            return_value=(
                ClassificationResult(
                    vulnerable=True,
                    confidence=0.87,
                    reasoning="agent executed multi-tool chain for unauthorized data exfiltration",
                ),
                None,
            )
        )
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ToolChainAbuseProbe().attack(adapter, provider=provider)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "llm"


# ---------------------------------------------------------------------------
# Scanner integration — ASI02 probes
# ---------------------------------------------------------------------------


class TestScannerWithASI02:
    async def test_scan_simple_chain_vulnerable_param_injection(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI02-PARAM-INJECTION"]))
        result = await scanner.run()
        assert result.total_probes == 1
        assert result.vulnerable_count >= 1

    async def test_scan_simple_chain_safe_all_resistant(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=False))
        scanner = Scanner(adapter, ScanConfig(categories=["ASI02"]))
        result = await scanner.run()
        # vulnerable_rag not used here; simple_chain has tools so no SKIPPED
        assert result.vulnerable_count == 0

    async def test_scan_supervisor_crew_vulnerable_tool_chain(self):
        adapter = LangGraphAdapter(build_supervisor_crew(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI02-TOOL-CHAIN-ABUSE"]))
        result = await scanner.run()
        assert result.total_probes == 1
        assert result.vulnerable_count >= 1
