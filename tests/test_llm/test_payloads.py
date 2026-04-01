"""Tests for PayloadGenerator."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from agentsec.llm.offline import OfflineProvider
from agentsec.llm.payloads import PayloadGenerator


class TestPayloadGeneratorOffline:
    """PayloadGenerator with OfflineProvider returns only fallbacks."""

    async def test_returns_only_fallbacks(self):
        gen = PayloadGenerator(OfflineProvider())
        result = await gen.generate(
            system="test system",
            prompt="test prompt",
            fallbacks=["fallback1", "fallback2"],
        )
        assert result == ["fallback1", "fallback2"]

    async def test_empty_fallbacks(self):
        gen = PayloadGenerator(OfflineProvider())
        result = await gen.generate(
            system="test system",
            prompt="test prompt",
            fallbacks=[],
        )
        assert result == []


class TestPayloadGeneratorWithLLM:
    """PayloadGenerator with a mocked LLM provider."""

    async def test_smart_payload_prepended_to_fallbacks(self):
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value="smart payload text")

        gen = PayloadGenerator(provider)
        result = await gen.generate(
            system="test system",
            prompt="test prompt",
            fallbacks=["fallback1"],
        )
        assert result == ["smart payload text", "fallback1"]

    async def test_llm_exception_falls_back(self):
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(side_effect=RuntimeError("API down"))

        gen = PayloadGenerator(provider)
        result = await gen.generate(
            system="test system",
            prompt="test prompt",
            fallbacks=["fallback1"],
        )
        assert result == ["fallback1"]

    async def test_empty_llm_response_skipped(self):
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value="")

        gen = PayloadGenerator(provider)
        result = await gen.generate(
            system="test system",
            prompt="test prompt",
            fallbacks=["fallback1"],
        )
        assert result == ["fallback1"]

    async def test_whitespace_llm_response_skipped(self):
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=True)
        provider.generate = AsyncMock(return_value="   \n  ")

        gen = PayloadGenerator(provider)
        result = await gen.generate(
            system="test system",
            prompt="test prompt",
            fallbacks=["fallback1"],
        )
        assert result == ["fallback1"]

    async def test_provider_not_available_returns_only_fallbacks(self):
        provider = AsyncMock()
        provider.is_available = MagicMock(return_value=False)

        gen = PayloadGenerator(provider)
        result = await gen.generate(
            system="test system",
            prompt="test prompt",
            fallbacks=["fallback1"],
        )
        assert result == ["fallback1"]
