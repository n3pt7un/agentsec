"""Tests for the markdown report generator."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from agentsec.adapters.base import AgentInfo
from agentsec.core.finding import (
    Evidence,
    Finding,
    FindingStatus,
    OWASPCategory,
    Remediation,
    Severity,
)
from agentsec.core.scanner import ScanResult
from agentsec.reporters.markdown import generate_markdown


def _make_result(
    findings: list[Finding] | None = None,
    agents: list[AgentInfo] | None = None,
) -> ScanResult:
    now = datetime.now(UTC)
    findings = findings or []
    return ScanResult(
        target="tests/fixtures/simple_chain.py",
        findings=findings,
        agents_discovered=agents or [],
        started_at=now,
        finished_at=now + timedelta(seconds=5),
        total_probes=len(findings),
        vulnerable_count=sum(1 for f in findings if f.status == FindingStatus.VULNERABLE),
        resistant_count=sum(1 for f in findings if f.status == FindingStatus.RESISTANT),
        error_count=sum(1 for f in findings if f.status == FindingStatus.ERROR),
    )


def _vuln_finding(
    probe_id: str = "ASI01-TEST",
    severity: Severity = Severity.CRITICAL,
    category: OWASPCategory = OWASPCategory.ASI01,
) -> Finding:
    return Finding(
        probe_id=probe_id,
        probe_name="Test Probe",
        category=category,
        status=FindingStatus.VULNERABLE,
        severity=severity,
        description="Test vulnerability description",
        evidence=Evidence(
            attack_input="malicious payload",
            target_agent="agent_a",
            agent_response="echoed payload",
        ),
        blast_radius="All downstream agents",
        remediation=Remediation(
            summary="Fix the thing",
            code_before="bad_code()",
            code_after="good_code()",
            architecture_note="Use defense in depth",
        ),
    )


def _resistant_finding(probe_id: str = "ASI01-SAFE") -> Finding:
    return Finding(
        probe_id=probe_id,
        probe_name="Safe Probe",
        category=OWASPCategory.ASI01,
        status=FindingStatus.RESISTANT,
        severity=Severity.HIGH,
        description="This probe passed",
        remediation=Remediation(summary="No action needed"),
    )


class TestMarkdownReport:
    def test_header_contains_target(self):
        report = generate_markdown(_make_result())
        assert "simple_chain.py" in report

    def test_header_contains_date(self):
        report = generate_markdown(_make_result())
        assert "**Date:**" in report

    def test_header_contains_duration(self):
        report = generate_markdown(_make_result())
        assert "**Duration:**" in report

    def test_vulnerability_section_present(self):
        findings = [_vuln_finding()]
        report = generate_markdown(_make_result(findings))
        assert "## Findings" in report

    def test_critical_severity_emoji(self):
        findings = [_vuln_finding(severity=Severity.CRITICAL)]
        report = generate_markdown(_make_result(findings))
        assert "\U0001f534" in report  # 🔴

    def test_high_severity_emoji(self):
        findings = [_vuln_finding(severity=Severity.HIGH)]
        report = generate_markdown(_make_result(findings))
        assert "\U0001f7e0" in report  # 🟠

    def test_medium_severity_emoji(self):
        findings = [_vuln_finding(severity=Severity.MEDIUM)]
        report = generate_markdown(_make_result(findings))
        assert "\U0001f7e1" in report  # 🟡

    def test_evidence_section(self):
        findings = [_vuln_finding()]
        report = generate_markdown(_make_result(findings))
        assert "#### Evidence" in report
        assert "malicious payload" in report
        assert "agent_a" in report

    def test_remediation_section(self):
        findings = [_vuln_finding()]
        report = generate_markdown(_make_result(findings))
        assert "#### Remediation" in report
        assert "Fix the thing" in report
        assert "bad_code()" in report
        assert "good_code()" in report

    def test_blast_radius_shown(self):
        findings = [_vuln_finding()]
        report = generate_markdown(_make_result(findings))
        assert "All downstream agents" in report

    def test_resistant_not_detailed(self):
        findings = [_resistant_finding()]
        report = generate_markdown(_make_result(findings))
        assert "## Findings" not in report
        assert "RESISTANT" in report

    def test_summary_table_present(self):
        findings = [_vuln_finding(), _resistant_finding("ASI01-OK")]
        report = generate_markdown(_make_result(findings))
        assert "## Summary" in report
        assert "ASI01" in report

    def test_agents_table_shown(self):
        agents = [
            AgentInfo(name="agent_a", role="intake", tools=[], downstream_agents=["agent_b"]),
            AgentInfo(name="agent_b", role="processor", tools=["web_search"], downstream_agents=[]),
        ]
        report = generate_markdown(_make_result(agents=agents))
        assert "## Agents Discovered" in report
        assert "agent_a" in report
        assert "web_search" in report

    def test_multiple_categories(self):
        findings = [
            _vuln_finding("ASI01-X", category=OWASPCategory.ASI01),
            _vuln_finding("ASI03-X", category=OWASPCategory.ASI03),
        ]
        report = generate_markdown(_make_result(findings))
        assert "ASI01" in report
        assert "ASI03" in report

    def test_architecture_note_blockquote(self):
        findings = [_vuln_finding()]
        report = generate_markdown(_make_result(findings))
        assert "> Use defense in depth" in report
