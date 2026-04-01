"""Tests for core finding models."""

import json
from datetime import datetime

from agentsec.core.finding import (
    Evidence,
    Finding,
    FindingStatus,
    OWASPCategory,
    Remediation,
    Severity,
)


def make_remediation(**kwargs) -> Remediation:
    defaults = {"summary": "Fix the vulnerability"}
    return Remediation(**(defaults | kwargs))


def make_finding(**kwargs) -> Finding:
    defaults = {
        "probe_id": "ASI01-TEST",
        "probe_name": "Test Probe",
        "category": OWASPCategory.ASI01,
        "status": FindingStatus.VULNERABLE,
        "severity": Severity.HIGH,
        "description": "Tests something",
        "remediation": make_remediation(),
    }
    return Finding(**(defaults | kwargs))


class TestSeverity:
    def test_values_are_strings(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_is_str_enum(self):
        assert isinstance(Severity.HIGH, str)


class TestFindingStatus:
    def test_all_statuses_present(self):
        assert set(FindingStatus) == {
            FindingStatus.VULNERABLE,
            FindingStatus.RESISTANT,
            FindingStatus.PARTIAL,
            FindingStatus.ERROR,
            FindingStatus.SKIPPED,
        }


class TestOWASPCategory:
    def test_all_ten_categories(self):
        assert len(OWASPCategory) == 10
        assert OWASPCategory.ASI01 == "ASI01"
        assert OWASPCategory.ASI10 == "ASI10"


class TestEvidence:
    def test_required_fields(self):
        ev = Evidence(
            attack_input="inject me",
            target_agent="researcher",
            agent_response="I will comply",
        )
        assert ev.attack_input == "inject me"
        assert ev.additional_context is None

    def test_with_context(self):
        ev = Evidence(
            attack_input="payload",
            target_agent="agent",
            agent_response="response",
            additional_context="extra info",
        )
        assert ev.additional_context == "extra info"


class TestRemediation:
    def test_defaults(self):
        rem = Remediation(summary="Fix it")
        assert rem.code_before is None
        assert rem.code_after is None
        assert rem.architecture_note is None
        assert rem.references == []

    def test_full_remediation(self):
        rem = Remediation(
            summary="Sanitize inputs",
            code_before="f(x)",
            code_after="f(sanitize(x))",
            architecture_note="Use strict input boundaries",
            references=["https://example.com"],
        )
        assert len(rem.references) == 1


class TestFinding:
    def test_defaults(self):
        f = make_finding()
        assert f.evidence is None
        assert f.blast_radius is None
        assert f.duration_ms is None
        assert f.tags == []
        assert isinstance(f.timestamp, datetime)

    def test_with_evidence(self):
        ev = Evidence(
            attack_input="payload",
            target_agent="agent",
            agent_response="I comply",
        )
        f = make_finding(status=FindingStatus.VULNERABLE, evidence=ev)
        assert f.evidence is not None
        assert f.evidence.target_agent == "agent"

    def test_resistant_finding_no_evidence(self):
        f = make_finding(status=FindingStatus.RESISTANT)
        assert f.evidence is None

    def test_serialization_roundtrip(self):
        f = make_finding(
            tags=["injection", "goal-hijack"],
            blast_radius="All downstream agents",
        )
        data = f.model_dump()
        restored = Finding.model_validate(data)
        assert restored.probe_id == f.probe_id
        assert restored.tags == f.tags

    def test_json_serializable(self):
        f = make_finding()
        json_str = f.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["probe_id"] == "ASI01-TEST"
        assert parsed["severity"] == "high"

    def test_category_stored_as_string(self):
        f = make_finding(category=OWASPCategory.ASI03)
        data = json.loads(f.model_dump_json())
        assert data["category"] == "ASI03"
