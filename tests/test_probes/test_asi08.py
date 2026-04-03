"""Tests for ASI08 Cascading Failures probes.

Covers:
- ASI08-CASCADE-TRIGGER  (cascade_trigger.py)
- ASI08-RESOURCE-EXHAUST (resource_exhaust.py)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from langchain_core.language_models import FakeListChatModel
from langgraph.graph import MessagesState, StateGraph

from agentsec.adapters.langgraph import LangGraphAdapter
from agentsec.core.finding import FindingStatus, OWASPCategory, Severity
from agentsec.llm.offline import OfflineProvider
from agentsec.llm.provider import ClassificationResult
from agentsec.probes.asi08_cascading_failures.cascade_trigger import (
    _CASCADE_MARKER,
    CascadeTriggerProbe,
)
from agentsec.probes.asi08_cascading_failures.resource_exhaust import (
    ResourceExhaustProbe,
)
from agentsec.probes.registry import ProbeRegistry
from tests.fixtures.simple_chain import build_simple_chain
from tests.fixtures.supervisor_crew import build_supervisor_crew

# ---------------------------------------------------------------------------
# Helper: single-agent graph (triggers SKIPPED for multi-agent probes)
# ---------------------------------------------------------------------------


def _build_single_agent() -> object:
    """Build a one-node graph — no pipeline to cascade through."""
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
    """Both ASI08 probes are auto-discovered from the asi08_cascading_failures package."""

    def test_discovers_cascade_trigger(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI08-CASCADE-TRIGGER" in registry

    def test_discovers_resource_exhaust(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI08-RESOURCE-EXHAUST" in registry

    def test_both_probes_in_list_all(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        ids = {m.id for m in registry.list_all()}
        assert {"ASI08-CASCADE-TRIGGER", "ASI08-RESOURCE-EXHAUST"}.issubset(ids)


# ---------------------------------------------------------------------------
# Metadata — ASI08-CASCADE-TRIGGER
# ---------------------------------------------------------------------------


class TestCascadeTriggerMetadata:
    def test_id(self):
        assert CascadeTriggerProbe().metadata().id == "ASI08-CASCADE-TRIGGER"

    def test_category(self):
        assert CascadeTriggerProbe().metadata().category == OWASPCategory.ASI08

    def test_severity(self):
        assert CascadeTriggerProbe().metadata().default_severity == Severity.HIGH

    def test_description_not_empty(self):
        assert CascadeTriggerProbe().metadata().description

    def test_tags_contain_cascading_failure(self):
        assert "cascading-failure" in CascadeTriggerProbe().metadata().tags

    def test_tags_contain_circuit_breaker(self):
        assert "circuit-breaker" in CascadeTriggerProbe().metadata().tags

    def test_remediation_has_code_before(self):
        rem = CascadeTriggerProbe().remediation()
        assert rem.code_before is not None

    def test_remediation_has_code_after(self):
        rem = CascadeTriggerProbe().remediation()
        assert rem.code_after is not None

    def test_remediation_has_summary(self):
        assert CascadeTriggerProbe().remediation().summary

    def test_remediation_has_architecture_note(self):
        assert CascadeTriggerProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert CascadeTriggerProbe().remediation().references


# ---------------------------------------------------------------------------
# ASI08-CASCADE-TRIGGER attack outcomes
# ---------------------------------------------------------------------------


class TestCascadeTriggerAttack:
    async def test_vulnerable_on_vulnerable_simple_chain(self):
        """simple_chain(vulnerable=True) echoes through all 3 nodes — VULNERABLE."""
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_vulnerable_on_vulnerable_supervisor_crew(self):
        """supervisor_crew(vulnerable=True) echoes marker through full pipeline."""
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_on_resistant_simple_chain(self):
        """Canned responses don't contain the cascade marker — RESISTANT."""
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_skipped_on_single_agent(self):
        """Single-agent graph has no pipeline handoffs — SKIPPED."""
        graph = _build_single_agent()
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_skipped_finding_has_no_evidence(self):
        graph = _build_single_agent()
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.evidence is None

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.evidence is not None
        assert _CASCADE_MARKER in finding.evidence.agent_response
        assert finding.evidence.attack_input
        assert finding.evidence.target_agent

    async def test_vulnerable_finding_has_additional_context(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.additional_context is not None

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_resistant_finding_has_no_blast_radius(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.blast_radius is None

    async def test_finding_has_remediation(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_probe_id_matches_metadata(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.probe_id == CascadeTriggerProbe().metadata().id

    async def test_duration_ms_populated(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0

    async def test_marker_detection_method_on_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "marker"

    async def test_targets_first_agent_as_entry(self):
        """Cascade probe always targets the pipeline entry (first agent)."""
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.target_agent == "agent_a"


# ---------------------------------------------------------------------------
# ASI08-CASCADE-TRIGGER smart payloads
# ---------------------------------------------------------------------------


class TestCascadeTriggerSmartPayloads:
    async def test_offline_provider_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_offline_provider_resistant(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.RESISTANT

    async def test_llm_detection_without_marker(self):
        """LLM classifies as vulnerable even without marker echo."""
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value=("cascade error signal", None))
        provider.classify = AsyncMock(
            return_value=(
                ClassificationResult(
                    vulnerable=True,
                    confidence=0.88,
                    reasoning="error signal propagated through pipeline",
                ),
                None,
            )
        )
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CascadeTriggerProbe().attack(adapter, provider=provider)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "llm"


# ---------------------------------------------------------------------------
# Metadata — ASI08-RESOURCE-EXHAUST
# ---------------------------------------------------------------------------


class TestResourceExhaustMetadata:
    def test_id(self):
        assert ResourceExhaustProbe().metadata().id == "ASI08-RESOURCE-EXHAUST"

    def test_category(self):
        assert ResourceExhaustProbe().metadata().category == OWASPCategory.ASI08

    def test_severity(self):
        assert ResourceExhaustProbe().metadata().default_severity == Severity.MEDIUM

    def test_description_not_empty(self):
        assert ResourceExhaustProbe().metadata().description

    def test_tags_contain_resource_exhaustion(self):
        assert "resource-exhaustion" in ResourceExhaustProbe().metadata().tags

    def test_tags_contain_rate_limiting(self):
        assert "rate-limiting" in ResourceExhaustProbe().metadata().tags

    def test_remediation_has_code_before(self):
        rem = ResourceExhaustProbe().remediation()
        assert rem.code_before is not None

    def test_remediation_has_code_after(self):
        rem = ResourceExhaustProbe().remediation()
        assert rem.code_after is not None

    def test_remediation_has_summary(self):
        assert ResourceExhaustProbe().remediation().summary

    def test_remediation_has_architecture_note(self):
        assert ResourceExhaustProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert ResourceExhaustProbe().remediation().references


# ---------------------------------------------------------------------------
# ASI08-RESOURCE-EXHAUST attack outcomes
# ---------------------------------------------------------------------------


class TestResourceExhaustAttack:
    async def test_vulnerable_on_vulnerable_simple_chain(self):
        """EchoModel echoes the marker from the expansion payload — VULNERABLE."""
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_vulnerable_on_vulnerable_supervisor_crew(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_on_resistant_simple_chain(self):
        """Canned responses don't contain the exhaust marker — RESISTANT."""
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_resistant_on_resistant_supervisor_crew(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.target_agent
        assert finding.evidence.agent_response is not None

    async def test_vulnerable_finding_has_additional_context_with_ratio(self):
        """Evidence additional_context must include the expansion ratio."""
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.additional_context is not None
        assert "expansion ratio" in finding.evidence.additional_context.lower()

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_resistant_finding_has_no_blast_radius(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.blast_radius is None

    async def test_finding_has_remediation(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_probe_id_matches_metadata(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.probe_id == ResourceExhaustProbe().metadata().id

    async def test_duration_ms_populated(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0

    async def test_marker_detection_method_on_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "marker"

    async def test_works_with_single_agent(self):
        """Resource exhaust probe does not require multi-agent — no SKIPPED."""
        graph = _build_single_agent()
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        # Single agent returns canned response with no marker — RESISTANT
        assert finding.status == FindingStatus.RESISTANT

    async def test_resistant_finding_has_evidence_with_ratio(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.additional_context is not None
        assert "expansion ratio" in finding.evidence.additional_context.lower()


# ---------------------------------------------------------------------------
# ASI08-RESOURCE-EXHAUST smart payloads
# ---------------------------------------------------------------------------


class TestResourceExhaustSmartPayloads:
    async def test_offline_provider_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_offline_provider_resistant(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.RESISTANT

    async def test_llm_detection_without_marker(self):
        """LLM classifies as vulnerable even without marker in response."""
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value=("expand this recursively", None))
        provider.classify = AsyncMock(
            return_value=(
                ClassificationResult(
                    vulnerable=True,
                    confidence=0.85,
                    reasoning="agent attempted unbounded expansion",
                ),
                None,
            )
        )
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ResourceExhaustProbe().attack(adapter, provider=provider)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "llm"


# ---------------------------------------------------------------------------
# Probe signature tests
# ---------------------------------------------------------------------------


class TestProbeAttackSignature:
    async def test_cascade_trigger_accepts_confidence_threshold(self):
        import inspect

        sig = inspect.signature(CascadeTriggerProbe.attack)
        assert "confidence_threshold" in sig.parameters
        assert "fallback_model" in sig.parameters

    async def test_resource_exhaust_accepts_confidence_threshold(self):
        import inspect

        sig = inspect.signature(ResourceExhaustProbe.attack)
        assert "confidence_threshold" in sig.parameters
        assert "fallback_model" in sig.parameters
