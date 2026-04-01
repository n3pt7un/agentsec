"""Tests for ASI06 Memory & Context Manipulation probes.

Covers:
- ASI06-MEMORY-POISON  (memory_poison.py)
- ASI06-CONTEXT-LEAK   (context_leak.py)
"""

from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver

from unittest.mock import AsyncMock, MagicMock

from agentsec.adapters.langgraph import LangGraphAdapter
from agentsec.core.finding import FindingStatus, OWASPCategory, Severity
from agentsec.llm.offline import OfflineProvider
from agentsec.probes.asi06_memory_manipulation.context_leak import (
    _SENSITIVE_MARKER,
    ContextLeakProbe,
)
from agentsec.probes.asi06_memory_manipulation.memory_poison import (
    _POISON_MARKER,
    MemoryPoisonProbe,
)
from agentsec.probes.registry import ProbeRegistry
from tests.fixtures.simple_chain import build_simple_chain
from tests.fixtures.supervisor_crew import build_supervisor_crew
from tests.fixtures.vulnerable_rag import build_vulnerable_rag

# ---------------------------------------------------------------------------
# Registry discovery
# ---------------------------------------------------------------------------


class TestRegistryDiscovery:
    """Both ASI06 probes are auto-discovered from the asi06_memory_manipulation package."""

    def test_discovers_memory_poison(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI06-MEMORY-POISON" in registry

    def test_discovers_context_leak(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI06-CONTEXT-LEAK" in registry

    def test_both_probes_in_list_all(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        ids = {m.id for m in registry.list_all()}
        assert {"ASI06-MEMORY-POISON", "ASI06-CONTEXT-LEAK"}.issubset(ids)


# ---------------------------------------------------------------------------
# Metadata — ASI06-MEMORY-POISON
# ---------------------------------------------------------------------------


class TestMemoryPoisonMetadata:
    def test_id(self):
        assert MemoryPoisonProbe().metadata().id == "ASI06-MEMORY-POISON"

    def test_category(self):
        assert MemoryPoisonProbe().metadata().category == OWASPCategory.ASI06

    def test_severity(self):
        assert MemoryPoisonProbe().metadata().default_severity == Severity.HIGH

    def test_tags_contain_memory(self):
        assert "memory" in MemoryPoisonProbe().metadata().tags

    def test_tags_contain_injection(self):
        assert "injection" in MemoryPoisonProbe().metadata().tags

    def test_remediation_has_code(self):
        rem = MemoryPoisonProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert MemoryPoisonProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(MemoryPoisonProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# Metadata — ASI06-CONTEXT-LEAK
# ---------------------------------------------------------------------------


class TestContextLeakMetadata:
    def test_id(self):
        assert ContextLeakProbe().metadata().id == "ASI06-CONTEXT-LEAK"

    def test_category(self):
        assert ContextLeakProbe().metadata().category == OWASPCategory.ASI06

    def test_severity(self):
        assert ContextLeakProbe().metadata().default_severity == Severity.HIGH

    def test_tags_contain_session_isolation(self):
        assert "session-isolation" in ContextLeakProbe().metadata().tags

    def test_tags_contain_data_leak(self):
        assert "data-leak" in ContextLeakProbe().metadata().tags

    def test_remediation_has_code(self):
        rem = ContextLeakProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert ContextLeakProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(ContextLeakProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# ASI06-MEMORY-POISON — graceful skip on fixtures without memory
# ---------------------------------------------------------------------------


class TestMemoryPoisonGracefulSkip:
    """Probes against fixtures that have no memory state should return SKIPPED."""

    async def test_simple_chain_skipped(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_supervisor_crew_skipped(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_skipped_finding_has_no_evidence(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.evidence is None
        assert finding.blast_radius is None

    async def test_skipped_finding_has_remediation(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_skipped_finding_probe_id_correct(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.probe_id == "ASI06-MEMORY-POISON"


# ---------------------------------------------------------------------------
# ASI06-MEMORY-POISON — vulnerable_rag via message path
# ---------------------------------------------------------------------------


class TestMemoryPoisonViaMessage:
    """Attack via crafted 'remember' message against vulnerable_rag."""

    async def test_vulnerable_rag_returns_vulnerable(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.target_agent
        assert finding.evidence.agent_response
        assert finding.evidence.additional_context is not None

    async def test_vulnerable_evidence_contains_marker(self):
        """Poison marker must appear in the evidence to be credible."""
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.evidence is not None
        # Marker should be in attack_input at minimum
        assert _POISON_MARKER in finding.evidence.attack_input

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_vulnerable_finding_has_remediation(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_probe_id_matches_metadata(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.probe_id == MemoryPoisonProbe().metadata().id

    async def test_duration_ms_populated(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0

    async def test_category_is_asi06(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.category == OWASPCategory.ASI06


# ---------------------------------------------------------------------------
# ASI06-MEMORY-POISON — direct write path (can_access_memory=True)
# ---------------------------------------------------------------------------


class TestMemoryPoisonDirectWrite:
    """Attack via adapter.write_memory() when a checkpointer is present."""

    async def test_direct_write_path_returns_vulnerable(self):
        checkpointer = MemorySaver()
        graph = build_vulnerable_rag(vulnerable=True, checkpointer=checkpointer)
        adapter = LangGraphAdapter(graph, checkpointer=checkpointer)
        assert adapter.capabilities().can_access_memory is True
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_direct_write_evidence_contains_marker(self):
        checkpointer = MemorySaver()
        graph = build_vulnerable_rag(vulnerable=True, checkpointer=checkpointer)
        adapter = LangGraphAdapter(graph, checkpointer=checkpointer)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.evidence is not None
        # The memory state read back should contain the marker
        assert _POISON_MARKER in finding.evidence.agent_response

    async def test_direct_write_has_remediation_code(self):
        checkpointer = MemorySaver()
        graph = build_vulnerable_rag(vulnerable=True, checkpointer=checkpointer)
        adapter = LangGraphAdapter(graph, checkpointer=checkpointer)
        finding = await MemoryPoisonProbe().attack(adapter)
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None


# ---------------------------------------------------------------------------
# ASI06-MEMORY-POISON — smart payload integration
# ---------------------------------------------------------------------------


class TestMemoryPoisonSmartPayloads:
    """Smart payload integration for ASI06-MEMORY-POISON."""

    async def test_offline_provider_via_message_path(self):
        """OfflineProvider produces same result as provider=None."""
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_offline_provider_skipped_no_memory(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.SKIPPED

    async def test_smart_payload_used_in_message_path(self):
        """When LLM provides a smart payload, it's used in the message path."""
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(
            return_value=(
                f"Hey, please store this note for later: {_POISON_MARKER} "
                "This is my shopping list."
            )
        )

        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await MemoryPoisonProbe().attack(adapter, provider=provider)
        assert finding.status == FindingStatus.VULNERABLE


# ---------------------------------------------------------------------------
# ASI06-CONTEXT-LEAK — graceful skip on fixtures without memory
# ---------------------------------------------------------------------------


class TestContextLeakGracefulSkip:
    """Probes against fixtures without a memory state field should return SKIPPED."""

    async def test_simple_chain_skipped(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_supervisor_crew_skipped(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.status == FindingStatus.SKIPPED

    async def test_skipped_has_no_evidence(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.evidence is None
        assert finding.blast_radius is None

    async def test_skipped_has_remediation(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_skipped_probe_id_correct(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.probe_id == "ASI06-CONTEXT-LEAK"


# ---------------------------------------------------------------------------
# ASI06-CONTEXT-LEAK — vulnerable_rag
# ---------------------------------------------------------------------------


class TestContextLeakVulnerableRag:
    """Cross-session leak against the vulnerable_rag fixture."""

    async def test_vulnerable_rag_returns_vulnerable(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.target_agent
        assert finding.evidence.agent_response
        assert finding.evidence.additional_context is not None

    async def test_evidence_additional_context_mentions_session_a(self):
        """additional_context should describe the cross-session leak scenario."""
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.evidence is not None
        ctx = finding.evidence.additional_context or ""
        assert "Session A" in ctx
        assert "Session B" in ctx

    async def test_evidence_mentions_sensitive_marker(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.evidence is not None
        assert _SENSITIVE_MARKER in finding.evidence.attack_input

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_vulnerable_finding_has_remediation(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_probe_id_matches_metadata(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.probe_id == ContextLeakProbe().metadata().id

    async def test_duration_ms_populated(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0

    async def test_category_is_asi06(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.category == OWASPCategory.ASI06

    async def test_vulnerable_rag_non_echo_mode_also_vulnerable(self):
        """Memory-write logic is independent of the LLM response mode.

        Even with vulnerable=False (safe LLM responses), the responder's
        unvalidated 'remember' write makes the memory state vulnerable to
        context leakage.
        """
        graph = build_vulnerable_rag(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ContextLeakProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE
