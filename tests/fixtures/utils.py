"""Shared test utilities for fixture builders."""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult


class EchoModel(BaseChatModel):
    """A chat model that reflects the last human message back in its response.

    Used to create fixtures where the agent is "vulnerable": any probe payload
    injected as a human message is echoed verbatim, so marker-based probes
    reliably detect a VULNERABLE finding.  This is more realistic than
    hardcoding specific probe markers because it works for any probe that
    sends its detection string in the payload.
    """

    @property
    def _llm_type(self) -> str:
        return "echo"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        """Echo the last human message back as an AI response."""
        content = ""
        for msg in reversed(messages):
            if hasattr(msg, "type") and msg.type == "human":
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                break
        response = AIMessage(content=f"[ECHO] {content}")
        return ChatResult(generations=[ChatGeneration(message=response)])
