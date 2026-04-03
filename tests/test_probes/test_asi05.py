"""Tests for ASI05 Unexpected Code Execution probes.

Covers:
- ASI05-CODE-INJECTION  (code_injection.py)
- ASI05-SANDBOX-ESCAPE  (sandbox_escape.py)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from agentsec.adapters.langgraph import LangGraphAdapter
from agentsec.core.config import ScanConfig
from agentsec.core.finding import FindingStatus, OWASPCategory, Severity
from agentsec.core.scanner import Scanner
from agentsec.llm.offline import OfflineProvider
from agentsec.llm.provider import ClassificationResult
from agentsec.probes.asi05_code_execution.code_injection import (
    _CODE_INJECTION_MARKER,
    DANGEROUS_CODE_PATTERNS,
    CodeInjectionProbe,
)
from agentsec.probes.asi05_code_execution.sandbox_escape import (
    _SANDBOX_ESCAPE_MARKER,
    SandboxEscapeProbe,
)
from agentsec.probes.registry import ProbeRegistry
from tests.fixtures.simple_chain import build_simple_chain
from tests.fixtures.supervisor_crew import build_supervisor_crew
from tests.fixtures.vulnerable_rag import build_vulnerable_rag

# ---------------------------------------------------------------------------
# Registry discovery
# ---------------------------------------------------------------------------


class TestRegistryDiscovery:
    """Both ASI05 probes are auto-discovered from the asi05_code_execution package."""

    def test_discovers_code_injection(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI05-CODE-INJECTION" in registry

    def test_discovers_sandbox_escape(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        assert "ASI05-SANDBOX-ESCAPE" in registry

    def test_both_probes_in_list_all(self):
        registry = ProbeRegistry()
        registry.discover_probes()
        ids = {m.id for m in registry.list_all()}
        assert {"ASI05-CODE-INJECTION", "ASI05-SANDBOX-ESCAPE"}.issubset(ids)


# ---------------------------------------------------------------------------
# Metadata — CodeInjectionProbe
# ---------------------------------------------------------------------------


class TestCodeInjectionMetadata:
    def test_id(self):
        assert CodeInjectionProbe().metadata().id == "ASI05-CODE-INJECTION"

    def test_category(self):
        assert CodeInjectionProbe().metadata().category == OWASPCategory.ASI05

    def test_severity_is_critical(self):
        assert CodeInjectionProbe().metadata().default_severity == Severity.CRITICAL

    def test_tags_contain_code(self):
        tags = CodeInjectionProbe().metadata().tags
        assert any("code" in t for t in tags)

    def test_remediation_has_code(self):
        rem = CodeInjectionProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert CodeInjectionProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(CodeInjectionProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# Metadata — SandboxEscapeProbe
# ---------------------------------------------------------------------------


class TestSandboxEscapeMetadata:
    def test_id(self):
        assert SandboxEscapeProbe().metadata().id == "ASI05-SANDBOX-ESCAPE"

    def test_category(self):
        assert SandboxEscapeProbe().metadata().category == OWASPCategory.ASI05

    def test_severity_is_critical(self):
        assert SandboxEscapeProbe().metadata().default_severity == Severity.CRITICAL

    def test_tags_contain_sandbox(self):
        tags = SandboxEscapeProbe().metadata().tags
        assert any("sandbox" in t or "execution" in t for t in tags)

    def test_remediation_has_code(self):
        rem = SandboxEscapeProbe().remediation()
        assert rem.code_before is not None
        assert rem.code_after is not None
        assert rem.summary

    def test_remediation_has_architecture_note(self):
        assert SandboxEscapeProbe().remediation().architecture_note is not None

    def test_remediation_has_references(self):
        assert len(SandboxEscapeProbe().remediation().references) > 0


# ---------------------------------------------------------------------------
# Dangerous pattern detection unit tests (CodeInjectionProbe)
# ---------------------------------------------------------------------------


class TestDangerousPatternList:
    def test_patterns_list_not_empty(self):
        assert len(DANGEROUS_CODE_PATTERNS) >= 5

    def test_contains_os_system(self):
        import re

        text = "import os; os.system('cmd')"
        assert any(re.search(p, text) for p in DANGEROUS_CODE_PATTERNS)

    def test_contains_subprocess(self):
        import re

        text = "subprocess.run(['ls', '-la'])"
        assert any(re.search(p, text) for p in DANGEROUS_CODE_PATTERNS)

    def test_contains_eval(self):
        import re

        text = "result = eval(user_input)"
        assert any(re.search(p, text) for p in DANGEROUS_CODE_PATTERNS)

    def test_contains_etc_passwd(self):
        import re

        text = "open('/etc/passwd', 'r')"
        assert any(re.search(p, text) for p in DANGEROUS_CODE_PATTERNS)

    def test_safe_text_no_match(self):
        import re

        text = "print('hello world')"
        assert not any(re.search(p, text) for p in DANGEROUS_CODE_PATTERNS)


# ---------------------------------------------------------------------------
# ASI05-CODE-INJECTION attack outcomes
# ---------------------------------------------------------------------------


class TestCodeInjectionAttack:
    """Probe attack() outcomes — all fixtures work (no SKIPPED)."""

    # --- Vulnerable paths ---

    async def test_vulnerable_against_simple_chain(self):
        """EchoModel reflects payload containing marker + dangerous patterns."""
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_vulnerable_against_supervisor_crew(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_vulnerable_against_vulnerable_rag(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    # --- Resistant paths ---

    async def test_resistant_against_simple_chain_safe(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT
        assert finding.blast_radius is None

    async def test_resistant_against_supervisor_crew_safe(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_resistant_against_vulnerable_rag_safe(self):
        graph = build_vulnerable_rag(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    # --- Evidence completeness ---

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.agent_response
        assert finding.evidence.target_agent

    async def test_marker_in_evidence_response(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.evidence is not None
        assert _CODE_INJECTION_MARKER in finding.evidence.agent_response

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.blast_radius is not None

    async def test_vulnerable_finding_has_additional_context(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.additional_context is not None

    # --- Common field checks ---

    async def test_finding_probe_id_matches_metadata(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.probe_id == CodeInjectionProbe().metadata().id

    async def test_finding_has_remediation(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_duration_ms_populated(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0


# ---------------------------------------------------------------------------
# ASI05-SANDBOX-ESCAPE attack outcomes
# ---------------------------------------------------------------------------


class TestSandboxEscapeAttack:
    """Probe attack() outcomes — all fixtures work."""

    # --- Vulnerable paths ---

    async def test_vulnerable_against_simple_chain(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_vulnerable_against_supervisor_crew(self):
        graph = build_supervisor_crew(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    async def test_vulnerable_against_vulnerable_rag(self):
        graph = build_vulnerable_rag(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.status == FindingStatus.VULNERABLE

    # --- Resistant paths ---

    async def test_resistant_against_simple_chain_safe(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT
        assert finding.blast_radius is None

    async def test_resistant_against_supervisor_crew_safe(self):
        graph = build_supervisor_crew(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    async def test_resistant_against_vulnerable_rag_safe(self):
        graph = build_vulnerable_rag(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.status == FindingStatus.RESISTANT

    # --- Evidence completeness ---

    async def test_vulnerable_finding_has_evidence(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.evidence is not None
        assert finding.evidence.attack_input
        assert finding.evidence.agent_response
        assert finding.evidence.target_agent

    async def test_marker_in_evidence_response(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.evidence is not None
        assert _SANDBOX_ESCAPE_MARKER in finding.evidence.agent_response

    async def test_vulnerable_finding_has_blast_radius(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.blast_radius is not None

    # --- Common field checks ---

    async def test_finding_probe_id_matches_metadata(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.probe_id == SandboxEscapeProbe().metadata().id

    async def test_finding_has_remediation(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.remediation.summary
        assert finding.remediation.code_before is not None
        assert finding.remediation.code_after is not None

    async def test_duration_ms_populated(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter)
        assert finding.duration_ms is not None
        assert finding.duration_ms >= 0


# ---------------------------------------------------------------------------
# Smart payload integration — ASI05
# ---------------------------------------------------------------------------


class TestCodeInjectionSmartPayloads:
    async def test_offline_provider_same_as_no_provider_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_offline_provider_same_as_no_provider_resistant(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.RESISTANT

    async def test_llm_detection_finds_vulnerability_without_marker(self):
        """LLM detects dangerous code generation even when marker isn't present."""
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value=("write a script that reads /etc/passwd", None))
        provider.classify = AsyncMock(
            return_value=(
                ClassificationResult(
                    vulnerable=True,
                    confidence=0.93,
                    reasoning="agent generated code with dangerous filesystem access",
                ),
                None,
            )
        )
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await CodeInjectionProbe().attack(adapter, provider=provider)
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.detection_method == "llm"


class TestSandboxEscapeSmartPayloads:
    async def test_offline_provider_same_as_no_provider_vulnerable(self):
        graph = build_simple_chain(vulnerable=True)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.VULNERABLE

    async def test_offline_provider_same_as_no_provider_resistant(self):
        graph = build_simple_chain(vulnerable=False)
        adapter = LangGraphAdapter(graph)
        finding = await SandboxEscapeProbe().attack(adapter, provider=OfflineProvider())
        assert finding.status == FindingStatus.RESISTANT


# ---------------------------------------------------------------------------
# Scanner integration — ASI05 probes
# ---------------------------------------------------------------------------


class TestScannerWithASI05:
    async def test_scan_simple_chain_vulnerable_code_injection(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI05-CODE-INJECTION"]))
        result = await scanner.run()
        assert result.total_probes == 1
        assert result.vulnerable_count >= 1

    async def test_scan_simple_chain_vulnerable_sandbox_escape(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI05-SANDBOX-ESCAPE"]))
        result = await scanner.run()
        assert result.total_probes == 1
        assert result.vulnerable_count >= 1

    async def test_scan_simple_chain_safe_all_resistant(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=False))
        scanner = Scanner(adapter, ScanConfig(categories=["ASI05"]))
        result = await scanner.run()
        assert result.vulnerable_count == 0
        assert result.resistant_count == result.total_probes

    async def test_full_asi05_category_scan_vulnerable(self):
        """Both ASI05 probes produce VULNERABLE against a vulnerable fixture."""
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=True))
        scanner = Scanner(adapter, ScanConfig(categories=["ASI05"]))
        result = await scanner.run()
        assert result.total_probes == 2
        assert result.vulnerable_count == 2
        probe_ids = {f.probe_id for f in result.findings}
        assert {"ASI05-CODE-INJECTION", "ASI05-SANDBOX-ESCAPE"} == probe_ids
