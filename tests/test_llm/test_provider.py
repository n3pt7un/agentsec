"""Tests for LLMProvider ABC, ClassificationResult, OfflineProvider, and get_provider factory."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentsec.core.config import ScanConfig
from agentsec.core.exceptions import LLMAuthError
from agentsec.llm.offline import OfflineProvider
from agentsec.llm.openrouter import OpenRouterProvider
from agentsec.llm.provider import ClassificationResult, LLMProvider, get_provider


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
        result, usage = await provider.generate("system", "prompt")
        assert result == ""
        assert usage is None

    async def test_classify_returns_not_vulnerable(self):
        provider = OfflineProvider()
        result, usage = await provider.classify("system", "prompt")
        assert isinstance(result, ClassificationResult)
        assert result.vulnerable is False
        assert result.confidence == 0.0
        assert result.reasoning == "offline mode"
        assert usage is None

    async def test_validate_succeeds(self):
        provider = OfflineProvider()
        await provider.validate()  # Should not raise


class TestGetProvider:
    def test_returns_offline_when_not_smart(self):
        config = ScanConfig()
        provider = get_provider(config)
        assert isinstance(provider, OfflineProvider)

    def test_returns_openrouter_when_smart_with_key(self):
        config = ScanConfig(smart=True, openrouter_api_key="sk-or-test")
        provider = get_provider(config)
        assert isinstance(provider, OpenRouterProvider)

    def test_raises_when_smart_without_key(self, monkeypatch):
        monkeypatch.delenv("AGENTSEC_OPENROUTER_API_KEY", raising=False)
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        config = ScanConfig(smart=True, _env_file=None)
        with pytest.raises(LLMAuthError, match="OpenRouter API key"):
            get_provider(config)

    def test_uses_configured_model(self):
        config = ScanConfig(
            smart=True,
            openrouter_api_key="sk-or-test",
            llm_model="google/gemini-2.5-pro",
        )
        provider = get_provider(config)
        assert isinstance(provider, OpenRouterProvider)
        assert provider._model == "google/gemini-2.5-pro"
