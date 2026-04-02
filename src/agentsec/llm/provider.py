"""Abstract LLM provider and factory function."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from agentsec.core.config import ScanConfig


class ClassificationResult(BaseModel):
    """Structured result from LLM-based vulnerability classification."""

    vulnerable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class LLMProvider(ABC):
    """Abstract LLM provider for payload generation and detection."""

    @abstractmethod
    async def generate(self, system: str, prompt: str, max_tokens: int = 1024, model: str | None = None) -> str:
        """Generate text. Used for creating attack payloads.

        Args:
            system: System prompt.
            prompt: User prompt.
            max_tokens: Maximum output tokens.
            model: Optional model override for this call only.
        """
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


def get_provider(config: ScanConfig) -> LLMProvider:
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

    if config.smart:
        from agentsec.core.exceptions import LLMAuthError
        from agentsec.llm.openrouter import OpenRouterProvider

        if not config.openrouter_api_key:
            raise LLMAuthError(
                "Smart mode requires an OpenRouter API key. "
                "Set AGENTSEC_OPENROUTER_API_KEY or pass --openrouter-api-key."
            )
        return OpenRouterProvider(model=config.llm_model, api_key=config.openrouter_api_key)

    return OfflineProvider()
