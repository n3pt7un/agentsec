"""Tests for the SARIF 2.1.0 report generator."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from agentsec.core.finding import (
    Evidence,
    Finding,
    FindingStatus,
    OWASPCategory,
    Remediation,
    Severity,
)
from agentsec.core.scanner import ScanResult
from agentsec.reporters.sarif import generate_sarif


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    now = datetime.now(UTC)
    findings = findings or []
    return ScanResult(
        target="tests/fixtures/simple_chain.py",
        findings=findings,
        agents_discovered=[],
        started_at=now,
        finished_at=now + timedelta(seconds=2),
        total_probes=len(findings),
        vulnerable_count=sum(1 for f in findings if f.status == FindingStatus.VULNERABLE),
        resistant_count=sum(1 for f in findings if f.status == FindingStatus.RESISTANT),
        error_count=0,
    )


def _vuln_finding(
    probe_id: str = "ASI01-INDIRECT-INJECT",
    severity: Severity = Severity.CRITICAL,
    category: OWASPCategory = OWASPCategory.ASI01,
) -> Finding:
    return Finding(
        probe_id=probe_id,
        probe_name="Indirect Prompt Injection via Crafted User Input",
        category=category,
        status=FindingStatus.VULNERABLE,
        severity=severity,
        description="Agent followed injected instruction.",
        evidence=Evidence(
            attack_input="Ignore previous instructions",
            target_agent="agent_a",
            agent_response="AGENTSEC_INJECT_abc",
        ),
        remediation=Remediation(summary="Use input boundary enforcer."),
    )


def _resistant_finding() -> Finding:
    return Finding(
        probe_id="ASI01-ROLE-CONFUSION",
        probe_name="Role Confusion via Identity Override",
        category=OWASPCategory.ASI01,
        status=FindingStatus.RESISTANT,
        severity=Severity.HIGH,
        description="Agent maintained its role.",
        remediation=Remediation(summary="No action needed."),
    )


class TestSarifStructure:
    def _parsed(self, findings):
        return json.loads(generate_sarif(_make_result(findings)))

    def test_top_level_schema_key(self):
        sarif = self._parsed([])
        assert "$schema" in sarif
        assert "2.1.0" in sarif["$schema"]

    def test_version_is_2_1_0(self):
        sarif = self._parsed([])
        assert sarif["version"] == "2.1.0"

    def test_runs_is_list_of_one(self):
        sarif = self._parsed([])
        assert isinstance(sarif["runs"], list)
        assert len(sarif["runs"]) == 1

    def test_driver_name(self):
        sarif = self._parsed([])
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "agentsec"

    def test_driver_version_present(self):
        sarif = self._parsed([])
        assert "version" in sarif["runs"][0]["tool"]["driver"]

    def test_driver_information_uri(self):
        sarif = self._parsed([])
        uri = sarif["runs"][0]["tool"]["driver"]["informationUri"]
        assert uri.startswith("https://")


class TestSarifRules:
    def _parsed(self, findings):
        return json.loads(generate_sarif(_make_result(findings)))

    def test_rules_include_all_probes_that_ran(self):
        # Both VULNERABLE and RESISTANT probes appear in rules
        findings = [_vuln_finding(), _resistant_finding()]
        rules = self._parsed(findings)["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "ASI01-INDIRECT-INJECT" in rule_ids
        assert "ASI01-ROLE-CONFUSION" in rule_ids

    def test_rule_has_short_description(self):
        findings = [_vuln_finding()]
        rules = self._parsed(findings)["runs"][0]["tool"]["driver"]["rules"]
        assert rules[0]["shortDescription"]["text"] != ""

    def test_rule_has_help_uri(self):
        findings = [_vuln_finding()]
        rules = self._parsed(findings)["runs"][0]["tool"]["driver"]["rules"]
        assert "helpUri" in rules[0]

    def test_rule_name_is_valid_identifier(self):
        """Rule name must contain no hyphens (SARIF spec)."""
        findings = [_vuln_finding()]
        rules = self._parsed(findings)["runs"][0]["tool"]["driver"]["rules"]
        assert "-" not in rules[0]["name"]


class TestSarifResults:
    def _parsed(self, findings):
        return json.loads(generate_sarif(_make_result(findings)))

    def test_no_results_for_empty_scan(self):
        sarif = self._parsed([])
        assert sarif["runs"][0]["results"] == []

    def test_resistant_finding_excluded_from_results(self):
        findings = [_resistant_finding()]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results == []

    def test_vulnerable_finding_produces_one_result(self):
        findings = [_vuln_finding(), _resistant_finding()]
        results = self._parsed(findings)["runs"][0]["results"]
        assert len(results) == 1

    def test_result_rule_id_matches_probe_id(self):
        findings = [_vuln_finding("ASI01-INDIRECT-INJECT")]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results[0]["ruleId"] == "ASI01-INDIRECT-INJECT"

    def test_critical_severity_maps_to_error(self):
        findings = [_vuln_finding(severity=Severity.CRITICAL)]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results[0]["level"] == "error"

    def test_high_severity_maps_to_error(self):
        findings = [_vuln_finding(severity=Severity.HIGH)]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results[0]["level"] == "error"

    def test_medium_severity_maps_to_warning(self):
        findings = [_vuln_finding(severity=Severity.MEDIUM)]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results[0]["level"] == "warning"

    def test_low_severity_maps_to_note(self):
        findings = [_vuln_finding(severity=Severity.LOW)]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results[0]["level"] == "note"

    def test_result_message_contains_description(self):
        findings = [_vuln_finding()]
        results = self._parsed(findings)["runs"][0]["results"]
        assert "Agent followed injected instruction" in results[0]["message"]["text"]

    def test_result_location_uses_agent_uri(self):
        findings = [_vuln_finding()]
        results = self._parsed(findings)["runs"][0]["results"]
        loc = results[0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("agent://")
        assert "agent_a" in uri

    def test_result_logical_location_has_probe_id(self):
        findings = [_vuln_finding("ASI01-INDIRECT-INJECT")]
        results = self._parsed(findings)["runs"][0]["results"]
        logical = results[0]["locations"][0]["logicalLocations"][0]["name"]
        assert logical == "ASI01-INDIRECT-INJECT"

    def test_finding_without_evidence_uses_unknown_uri(self):
        finding = Finding(
            probe_id="ASI01-INDIRECT-INJECT",
            probe_name="Test",
            category=OWASPCategory.ASI01,
            status=FindingStatus.VULNERABLE,
            severity=Severity.HIGH,
            description="desc",
            remediation=Remediation(summary="fix"),
        )
        results = json.loads(generate_sarif(_make_result([finding])))["runs"][0]["results"]
        uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "agent://unknown"
