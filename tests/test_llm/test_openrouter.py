"""Tests for OpenRouterProvider with mocked openai client."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentsec.core.exceptions import LLMAuthError, LLMTransientError
from agentsec.llm.openrouter import OpenRouterProvider
from agentsec.llm.provider import ClassificationResult, LLMProvider


class TestOpenRouterProviderBasics:
    def test_is_llm_provider(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        assert isinstance(provider, LLMProvider)

    def test_is_available_with_key(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        assert provider.is_available() is True

    def test_is_available_without_key(self):
        provider = OpenRouterProvider(model="test/model", api_key="")
        assert provider.is_available() is False


class TestOpenRouterGenerate:
    async def test_generate_returns_text(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="generated text"))]
        provider._client.chat.completions.create = AsyncMock(return_value=mock_response)

        result = await provider.generate("You are a red team assistant.", "Generate a payload")
        assert result == "generated text"

    async def test_generate_passes_correct_params(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        provider._client.chat.completions.create = AsyncMock(return_value=mock_response)

        await provider.generate("sys", "usr", max_tokens=512)
        call_kwargs = provider._client.chat.completions.create.call_args[1]
        assert call_kwargs["model"] == "test/model"
        assert call_kwargs["max_tokens"] == 512
        assert call_kwargs["messages"][0]["role"] == "system"
        assert call_kwargs["messages"][0]["content"] == "sys"
        assert call_kwargs["messages"][1]["role"] == "user"
        assert call_kwargs["messages"][1]["content"] == "usr"


class TestOpenRouterClassify:
    async def test_classify_parses_json_response(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(
            content='{"vulnerable": true, "confidence": 0.9, "reasoning": "marker found"}'
        ))]
        provider._client.chat.completions.create = AsyncMock(return_value=mock_response)

        result = await provider.classify("sys", "check this")
        assert isinstance(result, ClassificationResult)
        assert result.vulnerable is True
        assert result.confidence == 0.9

    async def test_classify_parses_not_vulnerable(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(
            content='{"vulnerable": false, "confidence": 0.1, "reasoning": "looks safe"}'
        ))]
        provider._client.chat.completions.create = AsyncMock(return_value=mock_response)

        result = await provider.classify("sys", "check this")
        assert result.vulnerable is False

    async def test_classify_handles_malformed_json_fallback(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="yes it is vulnerable"))]
        provider._client.chat.completions.create = AsyncMock(return_value=mock_response)

        result = await provider.classify("sys", "check this")
        assert isinstance(result, ClassificationResult)
        assert result.vulnerable is True


class TestOpenRouterRetry:
    async def test_retries_on_rate_limit(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        error_429 = _make_openai_error(429, "rate limited")
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        provider._client.chat.completions.create = AsyncMock(
            side_effect=[error_429, mock_response]
        )
        with patch("agentsec.llm.openrouter.asyncio.sleep", new_callable=AsyncMock):
            result = await provider.generate("sys", "prompt")
        assert result == "ok"

    async def test_retries_on_server_error(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        error_500 = _make_openai_error(500, "server error")
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        provider._client.chat.completions.create = AsyncMock(
            side_effect=[error_500, mock_response]
        )
        with patch("agentsec.llm.openrouter.asyncio.sleep", new_callable=AsyncMock):
            result = await provider.generate("sys", "prompt")
        assert result == "ok"

    async def test_raises_after_max_retries(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        error_429 = _make_openai_error(429, "rate limited")
        provider._client.chat.completions.create = AsyncMock(
            side_effect=[error_429, error_429, error_429]
        )
        with (
            patch("agentsec.llm.openrouter.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(LLMTransientError, match="rate limited"),
        ):
            await provider.generate("sys", "prompt")

    async def test_no_retry_on_auth_error(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        error_401 = _make_openai_error(401, "invalid key")
        provider._client.chat.completions.create = AsyncMock(side_effect=error_401)
        with pytest.raises(LLMAuthError, match="invalid key"):
            await provider.generate("sys", "prompt")
        assert provider._client.chat.completions.create.call_count == 1


class TestOpenRouterValidate:
    async def test_validate_success(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        provider._client.chat.completions.create = AsyncMock(return_value=mock_response)
        await provider.validate()

    async def test_validate_auth_failure(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-bad")
        error_401 = _make_openai_error(401, "invalid key")
        provider._client.chat.completions.create = AsyncMock(side_effect=error_401)
        with pytest.raises(LLMAuthError):
            await provider.validate()

    async def test_validate_transient_failure_retries(self):
        provider = OpenRouterProvider(model="test/model", api_key="sk-or-test")
        error_500 = _make_openai_error(500, "server error")
        provider._client.chat.completions.create = AsyncMock(
            side_effect=[error_500, error_500, error_500]
        )
        with (
            patch("agentsec.llm.openrouter.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(LLMTransientError),
        ):
            await provider.validate()


def _make_openai_error(status_code: int, message: str):
    """Create a mock OpenAI API error."""
    import httpx
    from openai import APIStatusError

    request = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
    response = httpx.Response(
        status_code=status_code,
        json={"error": {"message": message}},
        request=request,
    )
    return APIStatusError(message=message, response=response, body={"error": {"message": message}})
