"""Abstract LLM provider and factory function."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel


class ClassificationResult(BaseModel):
    """Structured result from LLM-based vulnerability classification."""

    vulnerable: bool
    confidence: float
    reasoning: str


class LLMProvider(ABC):
    """Abstract LLM provider for payload generation and detection."""

    @abstractmethod
    async def generate(self, system: str, prompt: str, max_tokens: int = 1024) -> str:
        """Generate text. Used for creating attack payloads."""
        ...

    @abstractmethod
    async def classify(self, system: str, prompt: str) -> ClassificationResult:
        """Classify a response for vulnerability indicators."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this provider is configured and ready."""
        ...

    @abstractmethod
    async def validate(self) -> None:
        """Eagerly check connectivity/auth. Raises LLMProviderError on failure."""
        ...


def get_provider(config) -> LLMProvider:
    """Return the best available provider based on config.

    Args:
        config: A ScanConfig instance.

    Returns:
        OpenRouterProvider if config.smart is True (requires API key),
        OfflineProvider otherwise.

    Raises:
        LLMAuthError: If smart mode is enabled but no API key is configured.
    """
    from agentsec.llm.offline import OfflineProvider

    if getattr(config, "smart", False):
        from agentsec.core.exceptions import LLMAuthError
        from agentsec.llm.openrouter import OpenRouterProvider

        api_key = getattr(config, "openrouter_api_key", None)
        if not api_key:
            raise LLMAuthError(
                "Smart mode requires an OpenRouter API key. "
                "Set AGENTSEC_OPENROUTER_API_KEY or pass --openrouter-api-key."
            )
        model = getattr(config, "llm_model", "anthropic/claude-sonnet-4")
        return OpenRouterProvider(model=model, api_key=api_key)

    return OfflineProvider()
