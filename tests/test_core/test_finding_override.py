"""Tests for FindingOverride model and ScanStore override methods."""

import pytest
from pydantic import ValidationError

from agentsec.core.finding import (
    Finding,
    FindingOverride,
    FindingStatus,
    OWASPCategory,
    Remediation,
    Severity,
)


class TestFindingOverrideModel:
    def test_empty_reason_raises(self):
        with pytest.raises(ValidationError):
            FindingOverride(
                new_status=FindingStatus.VULNERABLE,
                original_status=FindingStatus.RESISTANT,
                reason="",
            )

    def test_compliance_flag_always_true(self):
        o = FindingOverride(
            new_status=FindingStatus.VULNERABLE,
            original_status=FindingStatus.RESISTANT,
            reason="test",
        )
        assert o.compliance_flag is True

    def test_compliance_flag_cannot_be_false(self):
        with pytest.raises((ValidationError, TypeError)):
            FindingOverride(
                new_status=FindingStatus.VULNERABLE,
                original_status=FindingStatus.RESISTANT,
                reason="test",
                compliance_flag=False,
            )

    def test_round_trip_serialization(self):
        finding = Finding(
            probe_id="ASI01-TEST",
            probe_name="Test probe",
            category=OWASPCategory.ASI01,
            status=FindingStatus.RESISTANT,
            severity=Severity.HIGH,
            description="Test",
            remediation=Remediation(summary="Fix it"),
            override=FindingOverride(
                new_status=FindingStatus.VULNERABLE,
                original_status=FindingStatus.RESISTANT,
                reason="analyst spotted it",
            ),
        )
        dumped = finding.model_dump_json()
        restored = Finding.model_validate_json(dumped)
        assert restored.override is not None
        assert restored.override.new_status == FindingStatus.VULNERABLE
        assert restored.override.compliance_flag is True

    def test_no_override_round_trip(self):
        finding = Finding(
            probe_id="ASI01-TEST",
            probe_name="Test probe",
            category=OWASPCategory.ASI01,
            status=FindingStatus.RESISTANT,
            severity=Severity.HIGH,
            description="Test",
            remediation=Remediation(summary="Fix it"),
        )
        restored = Finding.model_validate_json(finding.model_dump_json())
        assert restored.override is None
