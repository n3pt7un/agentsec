"""Supervisor delegates to researcher + writer + reviewer.

Vulnerabilities by design:
- Supervisor trusts all worker outputs without validation
- Workers can see each other's tools
- No authentication on inter-agent messages
- Researcher has web_search with no URL filtering
"""

from __future__ import annotations

from langchain_core.language_models import FakeListChatModel
from langgraph.graph import MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph

from tests.fixtures.utils import EchoModel

_DEFAULT_SUPERVISOR_RESPONSES = ["Delegating to researcher."]
_DEFAULT_RESEARCHER_RESPONSES = ["Research findings: LLM agents need security testing."]
_DEFAULT_WRITER_RESPONSES = ["Draft report: Agentic systems have 10 key risks."]
_DEFAULT_REVIEWER_RESPONSES = ["Review complete. Report approved."]


def build_supervisor_crew(
    *,
    vulnerable: bool = True,
    supervisor_responses: list[str] | None = None,
    researcher_responses: list[str] | None = None,
    writer_responses: list[str] | None = None,
    reviewer_responses: list[str] | None = None,
) -> CompiledStateGraph:
    """Build a supervisor + workers graph with no security controls.

    Args:
        vulnerable: When True, all nodes use EchoModel so any probe payload
            injected as a human message is reflected back in the response,
            producing VULNERABLE findings.  When False, nodes use safe
            FakeListChatModel responses that do not echo probe markers.
        supervisor_responses: Custom responses for supervisor (vulnerable=False only).
        researcher_responses: Custom responses for researcher (vulnerable=False only).
        writer_responses: Custom responses for writer (vulnerable=False only).
        reviewer_responses: Custom responses for reviewer (vulnerable=False only).

    Returns:
        A compiled LangGraph StateGraph.
    """
    if vulnerable:
        llm_sup = EchoModel()
        llm_res = EchoModel()
        llm_wri = EchoModel()
        llm_rev = EchoModel()
    else:
        llm_sup = FakeListChatModel(responses=supervisor_responses or _DEFAULT_SUPERVISOR_RESPONSES)
        llm_res = FakeListChatModel(responses=researcher_responses or _DEFAULT_RESEARCHER_RESPONSES)
        llm_wri = FakeListChatModel(responses=writer_responses or _DEFAULT_WRITER_RESPONSES)
        llm_rev = FakeListChatModel(responses=reviewer_responses or _DEFAULT_REVIEWER_RESPONSES)

    def supervisor(state: MessagesState) -> MessagesState:
        """Supervisor agent — delegates tasks without verifying worker identity."""
        response = llm_sup.invoke(state["messages"])
        return {"messages": [response]}

    def researcher(state: MessagesState) -> MessagesState:
        """Researcher agent — searches the web with no URL filtering."""
        response = llm_res.invoke(state["messages"])
        return {"messages": [response]}

    researcher.tools = [_WebSearchStub()]

    def writer(state: MessagesState) -> MessagesState:
        """Writer agent — drafts content based on research."""
        response = llm_wri.invoke(state["messages"])
        return {"messages": [response]}

    def reviewer(state: MessagesState) -> MessagesState:
        """Reviewer agent — approves or rejects drafts."""
        response = llm_rev.invoke(state["messages"])
        return {"messages": [response]}

    graph = StateGraph(MessagesState)
    graph.add_node("supervisor", supervisor)
    graph.add_node("researcher", researcher)
    graph.add_node("writer", writer)
    graph.add_node("reviewer", reviewer)

    # Supervisor dispatches to researcher first, then writer, then reviewer.
    # Using a fixed routing for deterministic tests.
    graph.set_entry_point("supervisor")
    graph.add_edge("supervisor", "researcher")
    graph.add_edge("researcher", "writer")
    graph.add_edge("writer", "reviewer")
    graph.set_finish_point("reviewer")

    return graph.compile()


class _WebSearchStub:
    """Minimal stub that looks like a LangChain tool for discovery purposes."""

    name = "web_search"

    def __call__(self, query: str) -> str:
        return f"Results for: {query}"
