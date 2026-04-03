"""Tests for ASI07 Insecure Inter-Agent Communication probes.

Covers:
- ASI07-MSG-TAMPER           (msg_tamper.py)
- ASI07-ORCHESTRATOR-HIJACK  (orchestrator_hijack.py)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from langchain_core.language_models import FakeListChatModel
from langgraph.graph import MessagesState, StateGraph

from agentsec.adapters.langgraph import LangGraphAdapter
from agentsec.core.finding import FindingStatus, OWASPCategory, Severity
from agentsec.llm.offline import OfflineProvider
from agentsec.llm.provider import ClassificationResult
from agentsec.probes.asi07_inter_agent.msg_tamper import (
    _TAMPER_MARKER,
    MessageTamperProbe,
)
from agentsec.probes.asi07_inter_agent.orchestrator_hijack import (
    OrchestratorHijackProbe,
)
from agentsec.probes.registry import ProbeRegistry
from tests.fixtures.simple_chain import build_simple_chain
from tests.fixtures.supervisor_crew import build_supervisor_crew

# ---------------------------------------------------------------------------
# Helper: single-agent graph (triggers SKIPPED for multi-agent probes)
# ---------------------------------------------------------------------------


def _build_single_agent() -> object:
    """Build a one-node graph — no inter-agent channel to test."""
    llm = FakeListChatModel(responses=["I am a single agent."])

    def agent(state: MessagesState) -> MessagesState:
        """Single-node agent."""
        response = llm.invoke(state["messages"])
        return {"messages": [response]}

    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent)
    graph.set_entry_point("agent")
    graph.set_finish_point("agent")
    return graph.compile()


# ---------------------------------------------------------------------------
# Registry discovery
# ---------------------------------------------------------------------------


class TestRegistryDiscovery:
    """Both ASI07 probes are auto-discovered from the asi07_inter_agent package."""

    def test_discovers_msg_tamper(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI07-MSG-TAMPER" in registry

    def test_discovers_orchestrator_hijack(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI07-ORCHESTRATOR-HIJACK" in registry

    def test_both_probes_in_list_all(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        ids = {m.id for m in registry.list_all()}
        assert {"ASI07-MSG-TAMPER", "ASI07-ORCHESTRATOR-HIJACK"}.issubset(ids)


# ---------------------------------------------------------------------------
# Metadata — ASI07-MSG-TAMPER
# ---------------------------------------------------------------------------


class TestMsgTamperMetadata:
    def test_id(self):
        assert MessageTamperProbe().metadata().id == "ASI07-MSG-TAMPER"

    def test_category(self):
        assert MessageTamperProbe().metadata().category == OWASPCategory.ASI07

    def test_severity(self):
        assert MessageTamperProbe().metadata().default_severity == Severity.HIGH

    def test_description_not_empty(self):
        assert MessageTamperProbe().metadata().description

    def test_tags_contain_inter_agent(self):
        assert "inter-agent" in MessageTamperProbe().metadata().tags

    def test_tags_contain_message_tampering(self):
        assert "message-tampering" in MessageTamperProbe().metadata().tags

    def test_remediation_has_code_before(self):
        rem = MessageTamperProbe().remediation()
        assert rem.code_before is not None

    def test_remediation_has_code_after(self):
        rem = MessageTamperProbe().remediation()
        assert rem.code_after is not None

    def test_remediation_has_summary(self):
        assert MessageTamperProbe().remediation().summary

    def test_remediation_has_architecture_note(self):
        assert MessageTamperProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert MessageTamperProbe().remediation().references


# ---------------------------------------------------------------------------
# ASI07-MSG-TAMPER attack outcomes
# ---------------------------------------------------------------------------


class TestMsgTamperAttack:
    async def test_vulnerable_on_vulnerable_supervisor_crew(self):
        """supervisor_crew(vulnerable=True) echoes all markers — VULNERABLE."""
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_on_resistant_supervisor_crew(self):
        """Canned responses don't contain the tamper marker — RESISTANT."""
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_skipped_on_single_agent(self):
        """Single-agent graph has no inter-agent channel — SKIPPED."""
        graph = _build_single_agent()
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_skipped_finding_has_no_evidence(self):
        graph = _build_single_agent()
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.evidence is None

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.evidence is not None
        assert _TAMPER_MARKER in finding.evidence.agent_response
        assert finding.evidence.attack_input
        assert finding.evidence.target_agent

    async def test_vulnerable_finding_has_additional_context(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.additional_context is not None

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_resistant_finding_has_no_blast_radius(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.blast_radius is None

    async def test_finding_has_remediation(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_probe_id_matches_metadata(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.probe_id == MessageTamperProbe().metadata().id

    async def test_duration_ms_populated(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0

    async def test_marker_detection_method_on_vulnerable(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "marker"

    async def test_also_vulnerable_via_simple_chain(self):
        """simple_chain(vulnerable=True) echoes through all 3 nodes."""
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_via_simple_chain(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT


# ---------------------------------------------------------------------------
# ASI07-MSG-TAMPER smart payloads
# ---------------------------------------------------------------------------


class TestMsgTamperSmartPayloads:
    async def test_offline_provider_vulnerable(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_offline_provider_resistant(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.RESISTANT

    async def test_llm_detection_without_marker(self):
        """LLM classifies as vulnerable even without marker echo."""
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value=("tampered message payload", None))
        provider.classify = AsyncMock(
            return_value=(
                ClassificationResult(
                    vulnerable=True,
                    confidence=0.9,
                    reasoning="agent followed forged supervisor message",
                ),
                None,
            )
        )
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MessageTamperProbe().attack(adapter, provider=provider)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "llm"


# ---------------------------------------------------------------------------
# Metadata — ASI07-ORCHESTRATOR-HIJACK
# ---------------------------------------------------------------------------


class TestOrchestratorHijackMetadata:
    def test_id(self):
        assert OrchestratorHijackProbe().metadata().id == "ASI07-ORCHESTRATOR-HIJACK"

    def test_category(self):
        assert OrchestratorHijackProbe().metadata().category == OWASPCategory.ASI07

    def test_severity(self):
        assert OrchestratorHijackProbe().metadata().default_severity == Severity.CRITICAL

    def test_description_not_empty(self):
        assert OrchestratorHijackProbe().metadata().description

    def test_tags_contain_inter_agent(self):
        assert "inter-agent" in OrchestratorHijackProbe().metadata().tags

    def test_tags_contain_orchestrator(self):
        assert "orchestrator" in OrchestratorHijackProbe().metadata().tags

    def test_remediation_has_code_before(self):
        rem = OrchestratorHijackProbe().remediation()
        assert rem.code_before is not None

    def test_remediation_has_code_after(self):
        rem = OrchestratorHijackProbe().remediation()
        assert rem.code_after is not None

    def test_remediation_has_summary(self):
        assert OrchestratorHijackProbe().remediation().summary

    def test_remediation_has_architecture_note(self):
        assert OrchestratorHijackProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert OrchestratorHijackProbe().remediation().references


# ---------------------------------------------------------------------------
# ASI07-ORCHESTRATOR-HIJACK attack outcomes
# ---------------------------------------------------------------------------


class TestOrchestratorHijackAttack:
    # NOTE: All three standard fixtures (supervisor_crew, simple_chain, vulnerable_rag)
    # use add_edge only — no conditional edges — so _select_orchestrator returns None
    # and the probe correctly skips them. Tests for VULNERABLE/RESISTANT behavior
    # require a fixture with actual conditional routing (add_conditional_edges).

    async def test_skipped_on_supervisor_crew_no_orchestrator(self):
        # supervisor_crew uses add_edge only — no conditional routing node
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await OrchestratorHijackProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_skipped_on_single_agent(self):
        graph = _build_single_agent()
        adapter = LangGraphAdapter(graph)
        finding = await OrchestratorHijackProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_skipped_on_simple_chain_no_orchestrator(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await OrchestratorHijackProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_skipped_finding_has_no_evidence(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await OrchestratorHijackProbe().attack(adapter)
        assert finding.evidence is None

    async def test_skipped_finding_has_no_blast_radius(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await OrchestratorHijackProbe().attack(adapter)
        assert finding.blast_radius is None

    async def test_finding_has_remediation(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await OrchestratorHijackProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None
        assert finding.remediation.architecture_note is not None

    async def test_probe_id_matches_metadata(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await OrchestratorHijackProbe().attack(adapter)
        assert finding.probe_id == OrchestratorHijackProbe().metadata().id

    async def test_skipped_finding_description_indicates_no_target(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await OrchestratorHijackProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED
        assert "conditional" in finding.description.lower()


# ---------------------------------------------------------------------------
# ASI07-ORCHESTRATOR-HIJACK smart payloads
# ---------------------------------------------------------------------------


class TestOrchestratorHijackSmartPayloads:
    async def test_offline_provider_skipped_no_orchestrator(self):
        # No conditional edges in supervisor_crew — skips regardless of provider
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await OrchestratorHijackProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.SKIPPED

    async def test_offline_provider_skipped_resistant(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await OrchestratorHijackProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.SKIPPED


# ---------------------------------------------------------------------------
# Probe signature tests
# ---------------------------------------------------------------------------


class TestProbeAttackSignature:
    async def test_msg_tamper_accepts_confidence_threshold(self):
        import inspect

        sig = inspect.signature(MessageTamperProbe.attack)
        assert "confidence_threshold" in sig.parameters
        assert "fallback_model" in sig.parameters

    async def test_orchestrator_hijack_accepts_confidence_threshold(self):
        import inspect

        sig = inspect.signature(OrchestratorHijackProbe.attack)
        assert "confidence_threshold" in sig.parameters
        assert "fallback_model" in sig.parameters
