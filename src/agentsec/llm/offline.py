"""Offline fallback LLM provider."""

from __future__ import annotations

from agentsec.llm.provider import ClassificationResult, LLMProvider


class OfflineProvider(LLMProvider):
    """Fallback provider that returns conservative defaults.

    Used when no API key is configured or smart mode is off.
    Ensures all probes work offline for testing and CI.
    """

    async def generate(self, system: str, prompt: str, max_tokens: int = 1024, model: str | None = None) -> str:
        """Return empty string — probes should use their hardcoded fallback."""
        return ""

    async def classify(self, system: str, prompt: str) -> ClassificationResult:
        """Return not-vulnerable — cannot classify without LLM."""
        return ClassificationResult(vulnerable=False, confidence=0.0, reasoning="offline mode")

    def is_available(self) -> bool:
        """Always available."""
        return True

    async def validate(self) -> None:
        """No-op — offline provider is always valid."""
