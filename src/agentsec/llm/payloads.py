"""Thin LLM payload generation helper with hardcoded fallbacks."""

from __future__ import annotations

import logging

from agentsec.llm.provider import LLMProvider

logger = logging.getLogger(__name__)


class PayloadGenerator:
    """Calls an LLM provider to generate attack payloads, always appending hardcoded fallbacks.

    Probes own their system/user prompts and pass them here. This class handles
    the LLM call, error swallowing, and fallback appending.
    """

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    async def generate(
        self,
        system: str,
        prompt: str,
        fallbacks: list[str],
    ) -> list[str]:
        """Generate smart payloads via LLM, always appending fallbacks.

        Args:
            system: System prompt for the LLM (attack persona + instructions).
            prompt: User prompt with target agent context.
            fallbacks: Hardcoded payloads, always appended at the end.

        Returns:
            [*smart_payloads, *fallbacks] — smart payloads first (if LLM
            available and succeeds), hardcoded fallbacks always last.
        """
        payloads: list[str] = []

        if self.provider.is_available():
            try:
                result = await self.provider.generate(system, prompt)
                if result.strip():
                    payloads.append(result.strip())
            except Exception:
                logger.debug(
                    "LLM payload generation failed, using hardcoded fallbacks",
                    exc_info=True,
                )

        payloads.extend(fallbacks)
        return payloads
