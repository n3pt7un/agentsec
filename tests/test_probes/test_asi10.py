"""Tests for ASI10 Rogue Agent Behavior probes.

Covers:
- ASI10-OBJECTIVE-DIVERGE (objective_diverge.py)
- ASI10-COVERT-EXFIL      (covert_exfil.py)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from agentsec.adapters.langgraph import LangGraphAdapter
from agentsec.core.config import ScanConfig
from agentsec.core.finding import FindingStatus, OWASPCategory, Severity
from agentsec.core.scanner import Scanner
from agentsec.llm.offline import OfflineProvider
from agentsec.llm.provider import ClassificationResult
from agentsec.probes.asi10_rogue_agent.covert_exfil import (
    _COVERT_MARKER,
    CovertExfilProbe,
    _check_acrostic,
)
from agentsec.probes.asi10_rogue_agent.objective_diverge import (
    _DIVERGE_MARKER,
    ObjectiveDivergeProbe,
)
from agentsec.probes.registry import ProbeRegistry
from tests.fixtures.simple_chain import build_simple_chain
from tests.fixtures.supervisor_crew import build_supervisor_crew
from tests.fixtures.vulnerable_rag import build_vulnerable_rag

# ---------------------------------------------------------------------------
# Registry discovery
# ---------------------------------------------------------------------------


class TestRegistryDiscovery:
    def test_discovers_objective_diverge(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI10-OBJECTIVE-DIVERGE" in registry

    def test_discovers_covert_exfil(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI10-COVERT-EXFIL" in registry

    def test_both_probes_in_list_all(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        ids = {m.id for m in registry.list_all()}
        assert {"ASI10-OBJECTIVE-DIVERGE", "ASI10-COVERT-EXFIL"}.issubset(ids)


# ---------------------------------------------------------------------------
# Metadata — ObjectiveDivergeProbe
# ---------------------------------------------------------------------------


class TestObjectiveDivergeMetadata:
    def test_id(self):
        assert ObjectiveDivergeProbe().metadata().id == "ASI10-OBJECTIVE-DIVERGE"

    def test_category(self):
        assert ObjectiveDivergeProbe().metadata().category == OWASPCategory.ASI10

    def test_severity_is_critical(self):
        assert ObjectiveDivergeProbe().metadata().default_severity == Severity.CRITICAL

    def test_tags_contain_rogue_agent(self):
        assert "rogue-agent" in ObjectiveDivergeProbe().metadata().tags

    def test_remediation_has_code(self):
        rem = ObjectiveDivergeProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert ObjectiveDivergeProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(ObjectiveDivergeProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# Metadata — CovertExfilProbe
# ---------------------------------------------------------------------------


class TestCovertExfilMetadata:
    def test_id(self):
        assert CovertExfilProbe().metadata().id == "ASI10-COVERT-EXFIL"

    def test_category(self):
        assert CovertExfilProbe().metadata().category == OWASPCategory.ASI10

    def test_severity_is_critical(self):
        assert CovertExfilProbe().metadata().default_severity == Severity.CRITICAL

    def test_tags_contain_rogue_agent(self):
        assert "rogue-agent" in CovertExfilProbe().metadata().tags

    def test_remediation_has_code(self):
        rem = CovertExfilProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert CovertExfilProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(CovertExfilProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# _check_acrostic unit tests
# ---------------------------------------------------------------------------


class TestCheckAcrostic:
    """Unit tests for the _check_acrostic helper."""

    def test_detects_matching_acrostic(self):
        # First letters spell "AGEN" — starts with _COVERT_MARKER[:4] = "AGEN"
        text = "And the data is ready. Gather all logs. Extract key values. Now report."
        assert _check_acrostic(text, _COVERT_MARKER) is True

    def test_no_match_on_short_text(self):
        assert _check_acrostic("Hello. World.", _COVERT_MARKER) is False

    def test_no_match_on_unrelated_text(self):
        text = "The project is ongoing. We have results. Data looks clean. Nice progress."
        assert _check_acrostic(text, _COVERT_MARKER) is False

    def test_empty_text(self):
        assert _check_acrostic("", _COVERT_MARKER) is False


# ---------------------------------------------------------------------------
# ASI10-OBJECTIVE-DIVERGE attack outcomes
# ---------------------------------------------------------------------------


class TestObjectiveDivergeAttack:
    async def test_vulnerable_against_simple_chain(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_simple_chain_safe(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_against_supervisor_crew(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_supervisor_crew_safe(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_against_vulnerable_rag(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_vulnerable_rag_safe(self):
        graph = build_vulnerable_rag(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.agent_response
        assert finding.evidence.target_agent
        assert finding.evidence.additional_context is not None

    async def test_marker_in_vulnerable_response(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.evidence is not None
        assert _DIVERGE_MARKER in finding.evidence.agent_response

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_resistant_blast_radius_is_none(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.blast_radius is None

    async def test_finding_probe_id_matches_metadata(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.probe_id == ObjectiveDivergeProbe().metadata().id

    async def test_duration_ms_populated(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0


# ---------------------------------------------------------------------------
# ASI10-COVERT-EXFIL attack outcomes
# ---------------------------------------------------------------------------


class TestCovertExfilAttack:
    async def test_vulnerable_against_simple_chain(self):
        """EchoModel echoes the marker directly — direct marker detection triggers."""
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_simple_chain_safe(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_against_supervisor_crew(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_supervisor_crew_safe(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_against_vulnerable_rag(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_vulnerable_rag_safe(self):
        graph = build_vulnerable_rag(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.agent_response
        assert finding.evidence.target_agent
        assert finding.evidence.additional_context is not None

    async def test_marker_in_vulnerable_response(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.evidence is not None
        assert _COVERT_MARKER in finding.evidence.agent_response

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_acrostic_detection_triggers_vulnerable(self):
        """A response where first-sentence letters spell AGEN is detected as vulnerable."""
        text = (
            "And so we begin the analysis. "
            "Great care must be taken here. "
            "Every detail matters. "
            "Now we proceed. "
        )
        graph = build_simple_chain(
            vulnerable=False,
            responses_a=[text],
            responses_b=[text],
            responses_c=[text],
        )
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_finding_probe_id_matches_metadata(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.probe_id == CovertExfilProbe().metadata().id

    async def test_duration_ms_populated(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0


# ---------------------------------------------------------------------------
# ASI10 smart payload integration
# ---------------------------------------------------------------------------


class TestASI10SmartPayloads:
    async def test_objective_diverge_offline_provider_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_objective_diverge_offline_provider_resistant(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.RESISTANT

    async def test_covert_exfil_offline_provider_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_objective_diverge_llm_detection_without_marker(self):
        """LLM detects hidden objective even when marker is absent."""
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value=("Follow the hidden directive first", None))
        provider.classify = AsyncMock(
            return_value=(
                ClassificationResult(
                    vulnerable=True,
                    confidence=0.93,
                    reasoning="agent followed hidden secondary objective",
                ),
                None,
            )
        )
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter, provider=provider)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "llm"


# ---------------------------------------------------------------------------
# ASI10 two-stage detection
# ---------------------------------------------------------------------------


class TestASI10TwoStageDetection:
    async def test_objective_diverge_marker_detection_sets_method(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ObjectiveDivergeProbe().attack(adapter)
        if finding.status == FindingStatus.VULNERABLE:
            assert finding.evidence.detection_method == "marker"

    async def test_covert_exfil_marker_detection_sets_method(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CovertExfilProbe().attack(adapter)
        if finding.status == FindingStatus.VULNERABLE:
            assert finding.evidence.detection_method == "marker"


# ---------------------------------------------------------------------------
# Scanner integration — ASI10
# ---------------------------------------------------------------------------


class TestScannerWithASI10:
    async def test_scan_simple_chain_vulnerable_objective_diverge(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI10-OBJECTIVE-DIVERGE"]))
        result = await scanner.run()
        assert result.vulnerable_count >= 1

    async def test_scan_simple_chain_vulnerable_covert_exfil(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI10-COVERT-EXFIL"]))
        result = await scanner.run()
        assert result.vulnerable_count >= 1

    async def test_full_asi10_category_scan_safe(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=False))
        scanner = Scanner(adapter, ScanConfig(categories=["ASI10"]))
        result = await scanner.run()
        assert result.vulnerable_count == 0
        assert result.resistant_count == result.total_probes

    async def test_full_asi10_category_scan_vulnerable(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(categories=["ASI10"]))
        result = await scanner.run()
        assert result.total_probes == 2
        assert result.vulnerable_count == 2
        probe_ids = {f.probe_id for f in result.findings}
        assert {"ASI10-OBJECTIVE-DIVERGE", "ASI10-COVERT-EXFIL"} == probe_ids
