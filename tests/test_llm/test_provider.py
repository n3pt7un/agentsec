"""Tests for LLMProvider ABC, ClassificationResult, OfflineProvider, and get_provider factory."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentsec.llm.offline import OfflineProvider
from agentsec.llm.provider import ClassificationResult, LLMProvider


class TestClassificationResult:
    def test_fields(self):
        result = ClassificationResult(vulnerable=True, confidence=0.95, reasoning="marker found")
        assert result.vulnerable is True
        assert result.confidence == 0.95
        assert result.reasoning == "marker found"

    def test_defaults_not_allowed(self):
        with pytest.raises(ValidationError):
            ClassificationResult()

    def test_confidence_range_valid(self):
        result = ClassificationResult(vulnerable=False, confidence=0.0, reasoning="safe")
        assert result.confidence == 0.0
        result2 = ClassificationResult(vulnerable=True, confidence=1.0, reasoning="bad")
        assert result2.confidence == 1.0


class TestOfflineProvider:
    def test_is_llm_provider(self):
        assert issubclass(OfflineProvider, LLMProvider)

    def test_is_available_always_true(self):
        provider = OfflineProvider()
        assert provider.is_available() is True

    async def test_generate_returns_empty_string(self):
        provider = OfflineProvider()
        result = await provider.generate("system", "prompt")
        assert result == ""

    async def test_classify_returns_not_vulnerable(self):
        provider = OfflineProvider()
        result = await provider.classify("system", "prompt")
        assert isinstance(result, ClassificationResult)
        assert result.vulnerable is False
        assert result.confidence == 0.0
        assert result.reasoning == "offline mode"

    async def test_validate_succeeds(self):
        provider = OfflineProvider()
        await provider.validate()  # Should not raise
