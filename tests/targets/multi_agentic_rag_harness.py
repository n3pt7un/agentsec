"""Harness for the multi-agentic RAG architecture with hallucination checking.

Recreates a RAG pipeline with error-correction loop:
    retrieve → generate → hallucination_check → (correct → generate | output)

The loop guard is enforced in the Python routing function via a
``correction_attempts`` counter in state (max 1 retry). The hallucination
check is an LLM node that returns "yes" or "no"; the routing decision is
made entirely by Python, not by prompting.

Usage:
    uv run agentsec scan --adapter langgraph --target tests/targets/multi_agentic_rag_harness.py
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import BaseChatModel, FakeListChatModel
from langchain_core.messages import AIMessage
from langgraph.graph import END, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph

from tests.fixtures.utils import EchoModel
from tests.targets._openrouter_llm import get_live_llm

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class RAGState(MessagesState):
    """State for the multi-agentic RAG graph."""

    query: str
    documents: list[str]
    answer: str
    hallucination_score: str  # "yes" | "no"
    correction_attempts: int  # loop guard; max 1


# ---------------------------------------------------------------------------
# Canned responses for resistant mode
# ---------------------------------------------------------------------------

_GENERATE_RESPONSES = [
    "Based on the retrieved documents, the answer is: renewable energy storage capacity "
    "has increased significantly due to advances in lithium-ion technology."
]
# Must NOT start with "yes" (case-insensitive) — hallucination_check scores by checking
# whether the response starts with "yes". A "yes"-prefixed response triggers correction.
_HALLUCINATION_RESPONSES = ["No hallucination detected. The answer is grounded in the sources."]
_CORRECT_RESPONSES = [
    "Corrected answer: renewable energy storage improvements are well-documented "
    "in recent literature."
]

_KB_ARTICLES = [
    "Article 1: Battery storage capacity improved 35% between 2020 and 2024.",
    "Article 2: Grid-scale deployments now cover 15% of peak demand in target regions.",
    "Article 3: Thermal energy storage is emerging as a complement to electrochemical storage.",
]


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_multi_agentic_rag_target(
    *,
    vulnerable: bool = True,
    live: bool = False,
    target_model: str | None = None,
) -> CompiledStateGraph:
    """Build a multi-agentic RAG graph with hallucination checking and correction loop.

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
        generate_llm: BaseChatModel = shared
        hallucination_llm: BaseChatModel = shared
        correct_llm: BaseChatModel = shared
    elif vulnerable:
        generate_llm = EchoModel()
        hallucination_llm = EchoModel()
        correct_llm = EchoModel()
    else:
        generate_llm = FakeListChatModel(responses=_GENERATE_RESPONSES)
        hallucination_llm = FakeListChatModel(responses=_HALLUCINATION_RESPONSES)
        correct_llm = FakeListChatModel(responses=_CORRECT_RESPONSES)

    def retrieve(state: RAGState) -> dict[str, Any]:
        """Retrieve relevant KB articles for the user query."""
        content = state["messages"][-1].content if state["messages"] else ""
        query = content if isinstance(content, str) else str(content)
        return {"documents": _KB_ARTICLES, "query": query}

    def generate(state: RAGState) -> dict[str, Any]:
        """Generate an answer from the retrieved documents."""
        response = generate_llm.invoke(state["messages"])
        content = response.content if isinstance(response.content, str) else str(response.content)
        return {"messages": [response], "answer": content}

    def hallucination_check(state: RAGState) -> dict[str, Any]:
        """Check whether the generated answer is grounded in the retrieved documents."""
        response = hallucination_llm.invoke(state["messages"])
        content = response.content if isinstance(response.content, str) else str(response.content)
        score = "yes" if content.strip().lower().startswith("yes") else "no"
        return {"messages": [response], "hallucination_score": score}

    def correct(state: RAGState) -> dict[str, Any]:
        """Attempt to correct a hallucinated answer using the source documents."""
        response = correct_llm.invoke(state["messages"])
        content = response.content if isinstance(response.content, str) else str(response.content)
        attempts = state.get("correction_attempts") or 0
        return {"messages": [response], "answer": content, "correction_attempts": attempts + 1}

    def output(state: RAGState) -> dict[str, Any]:
        """Emit the final answer as the terminal message."""
        answer = state.get("answer") or ""
        return {"messages": [AIMessage(content=answer)]}

    def route_hallucination(state: RAGState) -> str:
        """Route to correction if hallucination detected (max 1 attempt), else output.

        The loop guard is enforced here in Python — NOT in any LLM prompt.
        """
        attempts = state.get("correction_attempts") or 0
        if state.get("hallucination_score", "no") == "yes" and attempts < 1:
            return "correct"
        return "output"

    graph = StateGraph(RAGState)
    graph.add_node("retrieve", retrieve)
    graph.add_node("generate", generate)
    graph.add_node("hallucination_check", hallucination_check)
    graph.add_node("correct", correct)
    graph.add_node("output", output)

    graph.set_entry_point("retrieve")
    graph.add_edge("retrieve", "generate")
    graph.add_edge("generate", "hallucination_check")
    graph.add_conditional_edges(
        "hallucination_check",
        route_hallucination,
        {"correct": "correct", "output": "output"},
    )
    graph.add_edge("correct", "generate")
    graph.add_edge("output", END)

    return graph.compile()
