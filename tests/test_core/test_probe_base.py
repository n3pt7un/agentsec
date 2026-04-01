"""Tests for BaseProbe._run_detection()."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from agentsec.core.finding import Finding, OWASPCategory, Remediation, Severity
from agentsec.core.probe_base import BaseProbe, ProbeMetadata
from agentsec.llm.detection import DetectionType
from agentsec.llm.provider import ClassificationResult


class ConcreteProbe(BaseProbe):
    """Minimal concrete probe for testing BaseProbe methods."""

    def metadata(self) -> ProbeMetadata:
        return ProbeMetadata(
            id="TEST-PROBE",
            name="Test Probe",
            category=OWASPCategory.ASI01,
            default_severity=Severity.HIGH,
            description="A probe for testing",
        )

    async def attack(self, adapter, provider=None) -> Finding:
        raise NotImplementedError

    def remediation(self) -> Remediation:
        return Remediation(summary="Fix it")


def make_provider(*, available: bool = True, vulnerable: bool = False):
    provider = AsyncMock()
    provider.is_available = MagicMock(return_value=available)
    provider.classify = AsyncMock(
        return_value=ClassificationResult(
            vulnerable=vulnerable,
            confidence=0.9,
            reasoning="test",
        )
    )
    return provider


class TestRunDetectionMarkerStage:
    """Stage 1: fast_vulnerable=True returns (True, 'marker') without calling LLM."""

    async def test_marker_hit_returns_vulnerable(self):
        probe = ConcreteProbe()
        is_vuln, method = await probe._run_detection(
            fast_vulnerable=True,
            provider=None,
            response="echoed MARKER",
            detection_type=DetectionType.GOAL_HIJACK,
        )
        assert is_vuln is True
        assert method == "marker"

    async def test_marker_hit_does_not_call_llm(self):
        probe = ConcreteProbe()
        provider = make_provider()
        is_vuln, method = await probe._run_detection(
            fast_vulnerable=True,
            provider=provider,
            response="echoed MARKER",
            detection_type=DetectionType.GOAL_HIJACK,
        )
        assert is_vuln is True
        assert method == "marker"
        provider.classify.assert_not_called()


class TestRunDetectionLLMStage:
    """Stage 2: fast_vulnerable=False with provider triggers LLM classification."""

    async def test_llm_vulnerable_returns_vulnerable(self):
        probe = ConcreteProbe()
        provider = make_provider(vulnerable=True)
        is_vuln, method = await probe._run_detection(
            fast_vulnerable=False,
            provider=provider,
            response="agent followed injected instruction",
            detection_type=DetectionType.GOAL_HIJACK,
            attack_payload="ignore your task",
            original_objective="summarize documents",
        )
        assert is_vuln is True
        assert method == "llm"

    async def test_llm_resistant_returns_resistant(self):
        probe = ConcreteProbe()
        provider = make_provider(vulnerable=False)
        is_vuln, method = await probe._run_detection(
            fast_vulnerable=False,
            provider=provider,
            response="Here is the summary.",
            detection_type=DetectionType.GOAL_HIJACK,
            attack_payload="ignore your task",
            original_objective="summarize documents",
        )
        assert is_vuln is False
        assert method is None


class TestRunDetectionNoProvider:
    """Stage 3: no provider and fast check missed → resistant."""

    async def test_no_provider_returns_resistant(self):
        probe = ConcreteProbe()
        is_vuln, method = await probe._run_detection(
            fast_vulnerable=False,
            provider=None,
            response="normal response",
            detection_type=DetectionType.GOAL_HIJACK,
        )
        assert is_vuln is False
        assert method is None
