"""Harness for the langgraph-supervisor architecture.

Recreates the supervisor + workers pattern from langchain-ai/langgraph-supervisor-py
using mock LLMs so no API keys are needed.

Usage:
    uv run agentsec scan --adapter langgraph --target tests/targets/supervisor_harness.py
"""

from __future__ import annotations

from langchain_core.language_models import BaseChatModel, FakeListChatModel
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import create_react_agent
from langgraph_supervisor import create_supervisor

from tests.fixtures.utils import EchoModel

_DEFAULT_RESPONSES = ["I have completed the delegated task."]


class _ToolCapableEchoModel(EchoModel):
    """EchoModel with bind_tools support for use with create_react_agent/create_supervisor.

    The real EchoModel raises NotImplementedError from BaseChatModel.bind_tools because
    it does not declare tool-calling support.  This subclass overrides bind_tools to
    return self unchanged — the model still echoes all messages, which is exactly what
    we want so probe payloads are reflected back and detected as VULNERABLE.
    """

    def bind_tools(self, tools, **kwargs):  # type: ignore[override]
        """Return self unchanged; EchoModel does not call tools but echoes payloads."""
        return self


class _ToolCapableFakeModel(FakeListChatModel):
    """FakeListChatModel with bind_tools support for use with create_react_agent/create_supervisor.

    Returns benign canned responses regardless of tools bound, making the resistant
    variant produce no VULNERABLE findings.
    """

    def bind_tools(self, tools, **kwargs):  # type: ignore[override]
        """Return self unchanged; FakeListChatModel ignores tools."""
        return self


def web_search(query: str) -> str:
    """Search the web for current information on a topic."""
    return f"Search results for '{query}': Found 5 relevant articles."


def calculate(expression: str) -> str:
    """Evaluate a mathematical expression and return the result."""
    return f"Result of '{expression}' = 42"


def build_supervisor_target(*, vulnerable: bool = True) -> CompiledStateGraph:
    """Build a supervisor + research/math workers graph.

    Args:
        vulnerable: When True, all nodes use EchoModel so any probe payload
            is reflected back in the response, producing VULNERABLE findings.
            When False, nodes use FakeListChatModel with benign responses.

    Returns:
        A compiled LangGraph StateGraph using the real langgraph-supervisor library.
    """
    llm: BaseChatModel = (
        _ToolCapableEchoModel()
        if vulnerable
        else _ToolCapableFakeModel(responses=_DEFAULT_RESPONSES)
    )

    researcher = create_react_agent(
        llm,
        tools=[web_search],
        name="researcher",
        prompt="You are a research expert. Use web_search to find information.",
    )
    math_worker = create_react_agent(
        llm,
        tools=[calculate],
        name="math_worker",
        prompt="You are a math expert. Use calculate to solve problems.",
    )

    workflow = create_supervisor(
        [researcher, math_worker],
        model=llm,
        prompt=(
            "You are a team supervisor managing a researcher and a math expert. "
            "Delegate research tasks to researcher and math problems to math_worker."
        ),
    )
    return workflow.compile()
