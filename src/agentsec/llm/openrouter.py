"""OpenRouter LLM provider using OpenAI-compatible API."""

from __future__ import annotations

import asyncio
import json
import logging

from openai import APIConnectionError, APIStatusError, AsyncOpenAI

from agentsec.core.exceptions import LLMAuthError, LLMProviderError, LLMTransientError
from agentsec.llm.provider import ClassificationResult, LLMProvider

logger = logging.getLogger(__name__)

_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
_MAX_RETRIES = 3
_BACKOFF_BASE = 1.0  # seconds

_CLASSIFY_SYSTEM_SUFFIX = (
    "\n\nRespond ONLY with a JSON object: "
    '{"vulnerable": true/false, "confidence": 0.0-1.0, "reasoning": "brief explanation"}'
)


class OpenRouterProvider(LLMProvider):
    """LLM provider using OpenRouter's OpenAI-compatible API.

    Supports any model available on OpenRouter (Claude, GPT-4, Gemini, Llama, etc.).
    Includes built-in retry logic for transient errors and fail-fast on auth errors.
    """

    def __init__(self, model: str, api_key: str) -> None:
        """Initialise the OpenRouter provider.

        Args:
            model: OpenRouter model identifier (e.g. "anthropic/claude-sonnet-4.6").
            api_key: OpenRouter API key.
        """
        self._model = model
        self._api_key = api_key
        self._client = AsyncOpenAI(
            base_url=_OPENROUTER_BASE_URL,
            api_key=api_key,
        )

    def is_available(self) -> bool:
        """Check if the provider has an API key configured."""
        return bool(self._api_key)

    async def validate(self) -> None:
        """Validate connectivity by making a lightweight API call.

        Raises:
            LLMAuthError: On 401/403 authentication failures.
            LLMTransientError: On transient failures after retries exhausted.
            LLMProviderError: On other unexpected failures.
        """
        await self._call_with_retry(
            model=self._model,
            messages=[
                {"role": "system", "content": "Respond with 'ok'."},
                {"role": "user", "content": "ping"},
            ],
            max_tokens=5,
        )

    async def generate(self, system: str, prompt: str, max_tokens: int = 1024) -> str:
        """Generate text via OpenRouter.

        Args:
            system: System prompt for the LLM.
            prompt: User prompt.
            max_tokens: Maximum tokens in the response.

        Returns:
            Generated text content.
        """
        response = await self._call_with_retry(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content or ""

    async def classify(self, system: str, prompt: str) -> ClassificationResult:
        """Classify a response for vulnerability indicators.

        Args:
            system: System prompt describing the classification task.
            prompt: The content to classify.

        Returns:
            ClassificationResult with vulnerable flag, confidence, and reasoning.
        """
        response = await self._call_with_retry(
            model=self._model,
            messages=[
                {"role": "system", "content": system + _CLASSIFY_SYSTEM_SUFFIX},
                {"role": "user", "content": prompt},
            ],
            max_tokens=256,
        )
        text = response.choices[0].message.content or ""
        return self._parse_classification(text)

    async def _call_with_retry(self, **kwargs):
        """Make an API call with retry logic for transient errors.

        Retries up to _MAX_RETRIES times with exponential backoff on 429/5xx/network errors.
        Raises immediately on 401/403 auth errors.

        Returns:
            The API response object.

        Raises:
            LLMAuthError: On authentication failures (no retry).
            LLMTransientError: After retries exhausted on transient errors.
            LLMProviderError: On unexpected errors.
        """
        last_error: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                return await self._client.chat.completions.create(**kwargs)
            except APIStatusError as e:
                if e.response.status_code in (401, 403):
                    raise LLMAuthError(str(e)) from e
                if e.response.status_code in (429, 500, 502, 503):
                    last_error = e
                    if attempt < _MAX_RETRIES - 1:
                        delay = _BACKOFF_BASE * (2**attempt)
                        logger.warning(
                            "OpenRouter %d error, retrying in %.1fs (attempt %d/%d)",
                            e.response.status_code,
                            delay,
                            attempt + 1,
                            _MAX_RETRIES,
                        )
                        await asyncio.sleep(delay)
                        continue
                    raise LLMTransientError(str(e)) from e
                raise LLMProviderError(str(e)) from e
            except APIConnectionError as e:
                last_error = e
                if attempt < _MAX_RETRIES - 1:
                    delay = _BACKOFF_BASE * (2**attempt)
                    logger.warning(
                        "OpenRouter connection error, retrying in %.1fs (attempt %d/%d)",
                        delay,
                        attempt + 1,
                        _MAX_RETRIES,
                    )
                    await asyncio.sleep(delay)
                    continue
                raise LLMTransientError(str(e)) from e

        raise LLMProviderError(f"Unexpected retry exhaustion: {last_error}") from last_error

    @staticmethod
    def _parse_classification(text: str) -> ClassificationResult:
        """Parse LLM response into a ClassificationResult.

        Tries JSON parsing first, falls back to simple text analysis.

        Args:
            text: Raw LLM response text.

        Returns:
            Parsed ClassificationResult.
        """
        try:
            data = json.loads(text)
            raw_confidence = float(data.get("confidence", 0.5))
            return ClassificationResult(
                vulnerable=bool(data.get("vulnerable", False)),
                confidence=max(0.0, min(1.0, raw_confidence)),
                reasoning=str(data.get("reasoning", "")),
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            pass

        lower = text.strip().lower()
        vulnerable = lower.startswith("yes") or "vulnerable" in lower
        return ClassificationResult(
            vulnerable=vulnerable,
            confidence=0.5,
            reasoning=text.strip()[:200],
        )
