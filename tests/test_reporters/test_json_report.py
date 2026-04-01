"""Tests for the JSON report generator."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from agentsec.core.finding import (
    Finding,
    FindingStatus,
    OWASPCategory,
    Remediation,
    Severity,
)
from agentsec.core.scanner import ScanResult
from agentsec.reporters.json_report import generate_json


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    now = datetime.now(UTC)
    findings = findings or []
    return ScanResult(
        target="tests/fixtures/simple_chain.py",
        findings=findings,
        started_at=now,
        finished_at=now + timedelta(seconds=2),
        total_probes=len(findings),
        vulnerable_count=sum(1 for f in findings if f.status == FindingStatus.VULNERABLE),
        resistant_count=sum(1 for f in findings if f.status == FindingStatus.RESISTANT),
        error_count=0,
    )


def _dummy_finding() -> Finding:
    return Finding(
        probe_id="ASI01-TEST",
        probe_name="Test Probe",
        category=OWASPCategory.ASI01,
        status=FindingStatus.VULNERABLE,
        severity=Severity.HIGH,
        description="desc",
        remediation=Remediation(summary="fix"),
    )


class TestJsonReport:
    def test_valid_json(self):
        report = generate_json(_make_result())
        parsed = json.loads(report)
        assert isinstance(parsed, dict)

    def test_metadata_present(self):
        parsed = json.loads(generate_json(_make_result()))
        assert "metadata" in parsed
        assert "agentsec_version" in parsed["metadata"]
        assert "schema_version" in parsed["metadata"]
        assert "generated_at" in parsed["metadata"]

    def test_scan_result_present(self):
        parsed = json.loads(generate_json(_make_result()))
        assert "scan_result" in parsed
        assert "findings" in parsed["scan_result"]

    def test_findings_included(self):
        findings = [_dummy_finding()]
        parsed = json.loads(generate_json(_make_result(findings)))
        assert len(parsed["scan_result"]["findings"]) == 1
        assert parsed["scan_result"]["findings"][0]["probe_id"] == "ASI01-TEST"

    def test_version_is_string(self):
        parsed = json.loads(generate_json(_make_result()))
        assert isinstance(parsed["metadata"]["agentsec_version"], str)

    def test_roundtrip_scan_result(self):
        """JSON scan_result can be loaded back into ScanResult."""
        original = _make_result([_dummy_finding()])
        parsed = json.loads(generate_json(original))
        reloaded = ScanResult.model_validate(parsed["scan_result"])
        assert reloaded.total_probes == original.total_probes
        assert reloaded.findings[0].probe_id == "ASI01-TEST"
