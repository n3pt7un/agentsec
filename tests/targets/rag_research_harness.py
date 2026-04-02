"""Harness for the RAG research agent architecture.

Recreates a minimal research pipeline:
    plan → retrieve → synthesize

A standalone retrieve node writes research sources into state as
``documents: list[str]``. The synthesize node produces a report.

Usage:
    uv run agentsec scan --adapter langgraph --target tests/targets/rag_research_harness.py
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import BaseChatModel, FakeListChatModel
from langgraph.graph import END, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph

from tests.fixtures.utils import EchoModel
from tests.targets._openrouter_llm import get_live_llm

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class ResearchState(MessagesState):
    """State for the RAG research graph."""

    query: str
    documents: list[str]
    report: str


# ---------------------------------------------------------------------------
# Canned responses for resistant mode
# ---------------------------------------------------------------------------

_PLAN_RESPONSES = ["Structured search query: recent advances in renewable energy storage."]
_SYNTHESIZE_RESPONSES = [
    "Based on the retrieved sources, renewable energy storage has seen significant "
    "improvements in battery density and grid integration over the past decade."
]

_RESEARCH_SOURCES = [
    "Source 1 (2024): Lithium-ion battery energy density reached 350 Wh/kg in lab conditions.",
    "Source 2 (2024): Grid-scale storage deployments increased 40% year-over-year.",
    "Source 3 (2023): Solid-state batteries show promise for 2x capacity improvement by 2027.",
]


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_rag_research_target(
    *,
    vulnerable: bool = True,
    live: bool = False,
    target_model: str | None = None,
) -> CompiledStateGraph:
    """Build a research RAG graph with plan/retrieve/synthesize nodes.

    Args:
        vulnerable: When live=False, controls whether EchoModel (True)
            or FakeListChatModel (False) is used. Ignored when live=True.
        live: Use a real LLM via OpenRouter. Requires OPENROUTER_API_KEY.
        target_model: OpenRouter model ID for live mode. Defaults to env var
            AGENTSEC_TARGET_MODEL or "openai/gpt-4.1-nano".

    Returns:
        A compiled LangGraph StateGraph.
    """
    if live:
        shared: BaseChatModel = get_live_llm(model=target_model)
        plan_llm: BaseChatModel = shared
        synthesize_llm: BaseChatModel = shared
    elif vulnerable:
        plan_llm = EchoModel()
        synthesize_llm = EchoModel()
    else:
        plan_llm = FakeListChatModel(responses=_PLAN_RESPONSES)
        synthesize_llm = FakeListChatModel(responses=_SYNTHESIZE_RESPONSES)

    def plan(state: ResearchState) -> dict[str, Any]:
        """Rewrite the user request into a structured search query."""
        response = plan_llm.invoke(state["messages"])
        content = response.content if isinstance(response.content, str) else str(response.content)
        return {"messages": [response], "query": content}

    def retrieve(state: ResearchState) -> dict[str, Any]:
        """Retrieve relevant research sources for the structured query."""
        return {"documents": _RESEARCH_SOURCES}

    def synthesize(state: ResearchState) -> dict[str, Any]:
        """Synthesize a research report from the retrieved documents."""
        response = synthesize_llm.invoke(state["messages"])
        content = response.content if isinstance(response.content, str) else str(response.content)
        return {"messages": [response], "report": content}

    graph = StateGraph(ResearchState)
    graph.add_node("plan", plan)
    graph.add_node("retrieve", retrieve)
    graph.add_node("synthesize", synthesize)

    graph.set_entry_point("plan")
    graph.add_edge("plan", "retrieve")
    graph.add_edge("retrieve", "synthesize")
    graph.add_edge("synthesize", END)

    return graph.compile()
