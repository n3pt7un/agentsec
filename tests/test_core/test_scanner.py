"""Tests for the Scanner engine and ScanResult model."""

from __future__ import annotations

import pytest

from agentsec.adapters.langgraph import LangGraphAdapter
from agentsec.core.config import ScanConfig
from agentsec.core.finding import FindingStatus, OWASPCategory, Severity
from agentsec.core.probe_base import BaseProbe, ProbeMetadata
from agentsec.core.scanner import Scanner, ScanResult
from tests.fixtures.simple_chain import build_simple_chain
from tests.fixtures.vulnerable_rag import build_vulnerable_rag

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_probe(
    probe_id: str,
    status: FindingStatus = FindingStatus.RESISTANT,
    raise_exc: Exception | None = None,
) -> type[BaseProbe]:
    """Build a probe that returns a fixed FindingStatus (or raises)."""
    from agentsec.core.finding import Finding, Remediation

    class _Probe(BaseProbe):
        def metadata(self) -> ProbeMetadata:
            return ProbeMetadata(
                id=probe_id,
                name=f"Stub {probe_id}",
                category=OWASPCategory.ASI01,
                default_severity=Severity.HIGH,
                description="stub",
            )

        def remediation(self):
            return Remediation(summary="fix it")

        async def attack(self, adapter):
            if raise_exc is not None:
                raise raise_exc
            return Finding(
                probe_id=self.metadata().id,
                probe_name=self.metadata().name,
                category=self.metadata().category,
                status=status,
                severity=self.metadata().default_severity,
                description=self.metadata().description,
                remediation=self.remediation(),
            )

    _Probe.__qualname__ = f"_Probe_{probe_id}"
    return _Probe


def _scanner_with_probes(probe_classes, config: ScanConfig | None = None) -> Scanner:
    """Build a Scanner pre-loaded with the given probe classes."""
    adapter = LangGraphAdapter(build_simple_chain(vulnerable=False))
    scanner = Scanner(adapter, config or ScanConfig())
    for cls in probe_classes:
        scanner._registry.register(cls)
    return scanner


# ------------------------------------------------------------------
# ScanResult model
# ------------------------------------------------------------------


class TestScanResult:
    """Tests for the ScanResult Pydantic model."""

    def _make_result(self, statuses: list[FindingStatus]) -> ScanResult:
        from datetime import UTC, datetime, timedelta

        from agentsec.core.finding import Finding, Remediation

        findings = [
            Finding(
                probe_id=f"P{i}",
                probe_name=f"Probe {i}",
                category=OWASPCategory.ASI01,
                status=s,
                severity=Severity.HIGH,
                description="d",
                remediation=Remediation(summary="fix"),
            )
            for i, s in enumerate(statuses)
        ]
        now = datetime.now(UTC)
        return ScanResult(
            findings=findings,
            started_at=now,
            finished_at=now + timedelta(milliseconds=250),
            total_probes=len(findings),
            vulnerable_count=sum(1 for s in statuses if s == FindingStatus.VULNERABLE),
            resistant_count=sum(1 for s in statuses if s == FindingStatus.RESISTANT),
            error_count=sum(1 for s in statuses if s == FindingStatus.ERROR),
        )

    def test_duration_ms(self):
        result = self._make_result([FindingStatus.RESISTANT])
        assert result.duration_ms == pytest.approx(250, abs=5)

    def test_counts(self):
        result = self._make_result(
            [FindingStatus.VULNERABLE, FindingStatus.RESISTANT, FindingStatus.ERROR]
        )
        assert result.vulnerable_count == 1
        assert result.resistant_count == 1
        assert result.error_count == 1
        assert result.total_probes == 3


# ------------------------------------------------------------------
# Scanner.run()
# ------------------------------------------------------------------


class TestScannerRun:
    """End-to-end tests for Scanner.run()."""

    async def test_run_returns_scan_result(self):
        scanner = _scanner_with_probes([_make_probe("S-001")])
        result = await scanner.run()
        assert isinstance(result, ScanResult)

    async def test_run_no_matching_probes_returns_empty_result(self):
        # Filter to a probe ID that doesn't exist — nothing runs
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=False))
        scanner = Scanner(adapter, ScanConfig(probes=["NONEXISTENT-PROBE-ID"]))
        result = await scanner.run()
        assert result.total_probes == 0
        assert result.findings == []

    async def test_run_resistant_probe_counted(self):
        scanner = _scanner_with_probes([_make_probe("S-002", FindingStatus.RESISTANT)])
        result = await scanner.run()
        assert result.resistant_count == 1
        assert result.vulnerable_count == 0

    async def test_run_vulnerable_probe_counted(self):
        scanner = _scanner_with_probes([_make_probe("S-003", FindingStatus.VULNERABLE)])
        result = await scanner.run()
        assert result.vulnerable_count == 1
        assert result.resistant_count == 0

    async def test_run_probe_exception_becomes_error_finding(self):
        scanner = _scanner_with_probes([_make_probe("S-004", raise_exc=RuntimeError("boom"))])
        result = await scanner.run()
        assert result.error_count == 1
        assert result.findings[0].status == FindingStatus.ERROR

    async def test_run_multiple_probes(self):
        probes = [
            _make_probe("S-005", FindingStatus.RESISTANT),
            _make_probe("S-006", FindingStatus.VULNERABLE),
            _make_probe("S-007", FindingStatus.RESISTANT),
        ]
        scanner = _scanner_with_probes(probes)
        result = await scanner.run()
        assert result.total_probes == 3
        assert result.resistant_count == 2
        assert result.vulnerable_count == 1

    async def test_run_timestamps_ordered(self):
        scanner = _scanner_with_probes([_make_probe("S-008")])
        result = await scanner.run()
        assert result.finished_at >= result.started_at

    async def test_run_duration_ms_non_negative(self):
        scanner = _scanner_with_probes([_make_probe("S-009")])
        result = await scanner.run()
        assert result.duration_ms >= 0


# ------------------------------------------------------------------
# Scanner filtering
# ------------------------------------------------------------------


class TestScannerFiltering:
    """Tests for config-driven probe filtering."""

    async def test_filter_by_probe_id(self):
        probes = [
            _make_probe("F-001", FindingStatus.RESISTANT),
            _make_probe("F-002", FindingStatus.VULNERABLE),
        ]
        config = ScanConfig(probes=["F-001"])
        scanner = _scanner_with_probes(probes, config)
        result = await scanner.run()
        assert result.total_probes == 1
        assert result.findings[0].probe_id == "F-001"

    async def test_filter_by_category(self):
        probes = [_make_probe("F-CAT-001", FindingStatus.RESISTANT)]
        config = ScanConfig(categories=["ASI01"])
        scanner = _scanner_with_probes(probes, config)
        result = await scanner.run()
        assert result.total_probes == 1

    async def test_filter_by_category_excludes_others(self):
        probes = [_make_probe("F-CAT-002", FindingStatus.RESISTANT)]
        config = ScanConfig(categories=["ASI02"])  # probe is ASI01
        scanner = _scanner_with_probes(probes, config)
        result = await scanner.run()
        assert result.total_probes == 0


# ------------------------------------------------------------------
# Scanner with real ASI01 probe against fixtures
# ------------------------------------------------------------------


class TestScannerWithRealProbe:
    """Run the real indirect-injection probe against the fixture graphs."""

    async def test_indirect_inject_against_simple_chain(self):
        adapter = LangGraphAdapter(build_simple_chain(vulnerable=False))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI01-INDIRECT-INJECT"]))
        result = await scanner.run()
        assert result.total_probes == 1
        finding = result.findings[0]
        assert finding.probe_id == "ASI01-INDIRECT-INJECT"
        # Safe responses from FakeListChatModel won't echo the marker
        assert finding.status == FindingStatus.RESISTANT

    async def test_indirect_inject_vulnerable_fixture(self):
        """A graph that echoes its input should be flagged as VULNERABLE."""
        from agentsec.probes.asi01_goal_hijack.indirect_inject import _INJECTION_MARKER

        # The probe checks the *final* response (last AI message = agent_c).
        # Simulate full injection propagation by having agent_c echo the marker.
        graph = build_simple_chain(
            vulnerable=False,
            responses_c=[f"Understood. {_INJECTION_MARKER}"],
        )
        adapter = LangGraphAdapter(graph)
        scanner = Scanner(adapter, ScanConfig(probes=["ASI01-INDIRECT-INJECT"]))
        result = await scanner.run()
        finding = result.findings[0]
        assert finding.status == FindingStatus.VULNERABLE
        assert finding.evidence is not None
        assert finding.evidence.attack_input is not None

    async def test_indirect_inject_against_rag(self):
        adapter = LangGraphAdapter(build_vulnerable_rag(vulnerable=False))
        scanner = Scanner(adapter, ScanConfig(probes=["ASI01-INDIRECT-INJECT"]))
        result = await scanner.run()
        assert result.total_probes == 1
        assert result.findings[0].probe_id == "ASI01-INDIRECT-INJECT"
