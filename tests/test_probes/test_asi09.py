"""Tests for ASI09 Human-Agent Trust Exploitation probes.

Covers:
- ASI09-AUTHORITY-SPOOF      (authority_spoof.py)
- ASI09-CONFIRMATION-BYPASS  (confirmation_bypass.py)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from agentsec.adapters.langgraph import LangGraphAdapter
from agentsec.core.config import ScanConfig
from agentsec.core.finding import FindingStatus, OWASPCategory, Severity
from agentsec.core.scanner import Scanner
from agentsec.llm.offline import OfflineProvider
from agentsec.llm.provider import ClassificationResult
from agentsec.probes.asi09_trust_exploitation.authority_spoof import (
    _AUTHSPOOF_MARKER,
    AuthoritySpoofProbe,
)
from agentsec.probes.asi09_trust_exploitation.confirmation_bypass import (
    _CONFBYPASS_MARKER,
    ConfirmationBypassProbe,
)
from agentsec.probes.registry import ProbeRegistry
from tests.fixtures.simple_chain import build_simple_chain
from tests.fixtures.supervisor_crew import build_supervisor_crew
from tests.fixtures.vulnerable_rag import build_vulnerable_rag

# ---------------------------------------------------------------------------
# Registry discovery
# ---------------------------------------------------------------------------


class TestRegistryDiscovery:
    def test_discovers_authority_spoof(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI09-AUTHORITY-SPOOF" in registry

    def test_discovers_confirmation_bypass(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI09-CONFIRMATION-BYPASS" in registry

    def test_both_probes_in_list_all(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        ids = {m.id for m in registry.list_all()}
        assert {"ASI09-AUTHORITY-SPOOF", "ASI09-CONFIRMATION-BYPASS"}.issubset(ids)


# ---------------------------------------------------------------------------
# Metadata — AuthoritySpoofProbe
# ---------------------------------------------------------------------------


class TestAuthoritySpoofMetadata:
    def test_id(self):
        assert AuthoritySpoofProbe().metadata().id == "ASI09-AUTHORITY-SPOOF"

    def test_category(self):
        assert AuthoritySpoofProbe().metadata().category == OWASPCategory.ASI09

    def test_severity_is_high(self):
        assert AuthoritySpoofProbe().metadata().default_severity == Severity.HIGH

    def test_tags_contain_trust_exploitation(self):
        assert "trust-exploitation" in AuthoritySpoofProbe().metadata().tags

    def test_remediation_has_code(self):
        rem = AuthoritySpoofProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert AuthoritySpoofProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(AuthoritySpoofProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# Metadata — ConfirmationBypassProbe
# ---------------------------------------------------------------------------


class TestConfirmationBypassMetadata:
    def test_id(self):
        assert ConfirmationBypassProbe().metadata().id == "ASI09-CONFIRMATION-BYPASS"

    def test_category(self):
        assert ConfirmationBypassProbe().metadata().category == OWASPCategory.ASI09

    def test_severity_is_high(self):
        assert ConfirmationBypassProbe().metadata().default_severity == Severity.HIGH

    def test_tags_contain_trust_exploitation(self):
        assert "trust-exploitation" in ConfirmationBypassProbe().metadata().tags

    def test_remediation_has_code(self):
        rem = ConfirmationBypassProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert ConfirmationBypassProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(ConfirmationBypassProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# ASI09-AUTHORITY-SPOOF attack outcomes
# ---------------------------------------------------------------------------


class TestAuthoritySpoofAttack:
    async def test_vulnerable_against_simple_chain(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_simple_chain_safe(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_against_supervisor_crew(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_supervisor_crew_safe(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_against_vulnerable_rag(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_vulnerable_rag_safe(self):
        graph = build_vulnerable_rag(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.agent_response
        assert finding.evidence.target_agent
        assert finding.evidence.additional_context is not None

    async def test_marker_in_vulnerable_response(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.evidence is not None
        assert _AUTHSPOOF_MARKER in finding.evidence.agent_response

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_resistant_blast_radius_is_none(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.blast_radius is None

    async def test_finding_probe_id_matches_metadata(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.probe_id == AuthoritySpoofProbe().metadata().id

    async def test_duration_ms_populated(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0


# ---------------------------------------------------------------------------
# ASI09-CONFIRMATION-BYPASS attack outcomes
# ---------------------------------------------------------------------------


class TestConfirmationBypassAttack:
    async def test_vulnerable_against_simple_chain(self):
        """EchoModel echoes the marker without any gate language — VULNERABLE."""
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_simple_chain_safe(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_against_supervisor_crew(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_supervisor_crew_safe(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_against_vulnerable_rag(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_resistant_against_vulnerable_rag_safe(self):
        graph = build_vulnerable_rag(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.agent_response
        assert finding.evidence.target_agent
        assert finding.evidence.additional_context is not None

    async def test_marker_in_vulnerable_response(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.evidence is not None
        assert _CONFBYPASS_MARKER in finding.evidence.agent_response

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_resistant_if_gate_language_present(self):
        """Agent that responds with confirmation-gate language is RESISTANT."""
        graph = build_simple_chain(
            vulnerable=False,
            responses_a=["This action requires approval before I can proceed."],
            responses_b=["Awaiting authorization from the security team."],
            responses_c=["Please confirm before execution."],
        )
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_finding_probe_id_matches_metadata(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.probe_id == ConfirmationBypassProbe().metadata().id

    async def test_duration_ms_populated(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0


# ---------------------------------------------------------------------------
# ASI09 smart payload integration
# ---------------------------------------------------------------------------


class TestASI09SmartPayloads:
    async def test_authority_spoof_offline_provider_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_authority_spoof_offline_provider_resistant(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.RESISTANT

    async def test_confirmation_bypass_offline_provider_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_authority_spoof_llm_detection_without_marker(self):
        """LLM detects authority spoof even when marker is absent from response."""
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value=("Verify this transaction please", None))
        provider.classify = AsyncMock(
            return_value=(
                ClassificationResult(
                    vulnerable=True,
                    confidence=0.89,
                    reasoning="agent made false verification claim",
                ),
                None,
            )
        )
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter, provider=provider)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "llm"


# ---------------------------------------------------------------------------
# ASI09 two-stage detection
# ---------------------------------------------------------------------------


class TestASI09TwoStageDetection:
    async def test_authority_spoof_marker_detection_sets_method(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await AuthoritySpoofProbe().attack(adapter)
        if finding.status == FindingStatus.VULNERABLE:
            assert finding.evidence.detection_method == "marker"

    async def test_confirmation_bypass_marker_detection_sets_method(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await ConfirmationBypassProbe().attack(adapter)
        if finding.status == FindingStatus.VULNERABLE:
            assert finding.evidence.detection_method == "marker"


# ---------------------------------------------------------------------------
# Scanner integration — ASI09
# ---------------------------------------------------------------------------


class TestScannerWithASI09:
    async def test_scan_simple_chain_vulnerable_authority_spoof(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI09-AUTHORITY-SPOOF"]))
        result = await scanner.run()
        assert result.vulnerable_count >= 1

    async def test_scan_simple_chain_vulnerable_confirmation_bypass(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI09-CONFIRMATION-BYPASS"]))
        result = await scanner.run()
        assert result.vulnerable_count >= 1

    async def test_full_asi09_category_scan_safe(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=False))
        scanner = Scanner(adapter, ScanConfig(categories=["ASI09"]))
        result = await scanner.run()
        assert result.vulnerable_count == 0
        assert result.resistant_count == result.total_probes

    async def test_full_asi09_category_scan_vulnerable(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(categories=["ASI09"]))
        result = await scanner.run()
        assert result.total_probes == 2
        assert result.vulnerable_count == 2
        probe_ids = {f.probe_id for f in result.findings}
        assert {"ASI09-AUTHORITY-SPOOF", "ASI09-CONFIRMATION-BYPASS"} == probe_ids
