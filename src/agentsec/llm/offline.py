"""Offline fallback LLM provider."""

from __future__ import annotations

from agentsec.core.finding import LLMUsage
from agentsec.llm.provider import ClassificationResult, LLMProvider


class OfflineProvider(LLMProvider):
    """Fallback provider that returns conservative defaults.

    Used when no API key is configured or smart mode is off.
    Ensures all probes work offline for testing and CI.
    """

    async def generate(
        self, system: str, prompt: str, max_tokens: int = 1024, model: str | None = None
    ) -> tuple[str, LLMUsage | None]:
        """Return empty string and no usage — probes use their hardcoded fallback."""
        return "", None

    async def classify(
        self, system: str, prompt: str
    ) -> tuple[ClassificationResult, LLMUsage | None]:
        """Return not-vulnerable and no usage — cannot classify without LLM."""
        result = ClassificationResult(vulnerable=False, confidence=0.0, reasoning="offline mode")
        return result, None

    def is_available(self) -> bool:
        """Always available."""
        return True

    async def validate(self) -> None:
        """No-op — offline provider is always valid."""
