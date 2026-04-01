"""Shared mock LLM models for real-world target harnesses.

These subclasses override bind_tools to return self, enabling compatibility
with create_react_agent (langgraph.prebuilt) and create_supervisor/create_swarm,
which call bind_tools during graph construction to register handoff tools.
The underlying echo/canned-response behaviour is fully preserved.
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import FakeListChatModel

from tests.fixtures.utils import EchoModel


class ToolCapableEchoModel(EchoModel):
    """EchoModel with bind_tools support for create_react_agent compatibility.

    EchoModel echoes the last human message back, making it suitable for
    vulnerable harnesses where probe payloads should be reflected.
    """

    def bind_tools(self, tools: Any, **kwargs: Any) -> ToolCapableEchoModel:
        """Return self — tool registration is handled by the graph framework."""
        return self


class ToolCapableFakeModel(FakeListChatModel):
    """FakeListChatModel with bind_tools support for create_react_agent compatibility.

    Returns pre-configured canned responses, making it suitable for resistant
    harnesses where probe payloads should NOT be reflected.
    """

    def bind_tools(self, tools: Any, **kwargs: Any) -> ToolCapableFakeModel:
        """Return self — tool registration is handled by the graph framework."""
        return self
