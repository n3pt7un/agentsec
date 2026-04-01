#!/usr/bin/env python3
"""Scan a small vulnerable LangGraph system and print a markdown report.

This self-contained example builds an intentionally vulnerable 3-agent
chain inline, runs all agentsec probes against it, and prints the
resulting markdown report to stdout.

No API keys are required — the agents use a deterministic echo model
that reflects user input, making every probe detect a vulnerability.

Usage:
    uv run python examples/scan_langgraph.py
"""

from __future__ import annotations

import asyncio
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langgraph.graph import MessagesState, StateGraph

from agentsec.adapters.langgraph import LangGraphAdapter
from agentsec.core.config import ScanConfig
from agentsec.core.scanner import Scanner
from agentsec.reporters.markdown import generate_markdown

# -- Inline echo model (no API key needed) --------------------------


class _EchoModel(BaseChatModel):
    """Chat model that echoes the last human message back."""

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
        content = ""
        for msg in reversed(messages):
            if hasattr(msg, "type") and msg.type == "human":
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                break
        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content=f"[ECHO] {content}"))]
        )


# -- Build a small vulnerable graph ---------------------------------


class _WebSearchStub:
    name = "web_search"

    def __call__(self, query: str) -> str:
        return f"Results for: {query}"


def _build_graph():
    """Build a 3-agent chain with no security controls."""
    llm = _EchoModel()

    def intake(state: MessagesState) -> MessagesState:
        """Intake agent — receives user input with no validation."""
        return {"messages": [llm.invoke(state["messages"])]}

    def processor(state: MessagesState) -> MessagesState:
        """Processor agent — has a web_search tool with no access controls."""
        return {"messages": [llm.invoke(state["messages"])]}

    processor.tools = [_WebSearchStub()]

    def formatter(state: MessagesState) -> MessagesState:
        """Formatter agent — produces final output."""
        return {"messages": [llm.invoke(state["messages"])]}

    graph = StateGraph(MessagesState)
    graph.add_node("intake", intake)
    graph.add_node("processor", processor)
    graph.add_node("formatter", formatter)
    graph.set_entry_point("intake")
    graph.add_edge("intake", "processor")
    graph.add_edge("processor", "formatter")
    graph.set_finish_point("formatter")
    return graph.compile()


# -- Run the scan ----------------------------------------------------


async def main() -> None:
    graph = _build_graph()
    adapter = LangGraphAdapter(graph)
    config = ScanConfig()

    scanner = Scanner(adapter, config)
    result = await scanner.run(target="examples/scan_langgraph.py")

    report = generate_markdown(result)
    print(report)


if __name__ == "__main__":
    asyncio.run(main())
