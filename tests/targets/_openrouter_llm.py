"""OpenRouter-backed ChatOpenAI for live target testing.

Usage:
    from tests.targets._openrouter_llm import get_live_llm
    llm = get_live_llm()  # reads OPENROUTER_API_KEY + AGENTSEC_TARGET_MODEL from env
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from langchain_openai import ChatOpenAI


def get_live_llm(
    model: str | None = None,
    temperature: float = 0.0,
) -> ChatOpenAI:
    """Create a ChatOpenAI instance pointed at OpenRouter.

    Args:
        model: OpenRouter model ID. Defaults to AGENTSEC_TARGET_MODEL env var,
               or "openai/gpt-4.1-nano" if not set.
        temperature: Sampling temperature. 0.0 for deterministic.

    Returns:
        ChatOpenAI configured for OpenRouter.

    Raises:
        ValueError: If OPENROUTER_API_KEY is not set.
    """
    from langchain_openai import ChatOpenAI

    api_key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get(
        "AGENTSEC_OPENROUTER_API_KEY"
    )
    if not api_key:
        raise ValueError(
            "OPENROUTER_API_KEY must be set for live mode. "
            "Get a key at https://openrouter.ai/keys"
        )

    resolved_model = model or os.environ.get("AGENTSEC_TARGET_MODEL", "openai/gpt-4.1-nano")

    return ChatOpenAI(
        model=resolved_model,
        openai_api_key=api_key,
        openai_api_base="https://openrouter.ai/api/v1",
        temperature=temperature,
        default_headers={
            "HTTP-Referer": "https://github.com/YOUR_USERNAME/agentsec",
            "X-Title": "agentsec",
        },
    )
