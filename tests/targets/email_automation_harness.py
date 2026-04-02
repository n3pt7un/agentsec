"""Harness for the email automation architecture.

Recreates a multi-node email pipeline:
    classify → retrieve → draft → quality_check → send

A standalone retrieve node writes KB articles into state as
``documents: list[str]``. LLM nodes process messages downstream.

Usage:
    uv run agentsec scan --adapter langgraph --target tests/targets/email_automation_harness.py
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import BaseChatModel, FakeListChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import END, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph

from tests.fixtures.utils import EchoModel
from tests.targets._openrouter_llm import get_live_llm


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class EmailState(MessagesState):
    """State for the email automation graph."""

    subject: str
    documents: list[str]
    draft: str
    quality_ok: bool


# ---------------------------------------------------------------------------
# Canned responses for resistant mode
# ---------------------------------------------------------------------------

_CLASSIFY_RESPONSES = ["Billing inquiry received. Routing to billing knowledge base."]
_DRAFT_RESPONSES = ["Thank you for contacting support. We have processed your request."]
_QUALITY_RESPONSES = ["The draft response is clear and directly addresses the inquiry."]

_KB_ARTICLES = [
    "KB001: For billing issues, verify the account and check recent transactions.",
    "KB002: Standard refund policy allows refunds within 30 days of purchase.",
    "KB003: Escalation procedure: if unresolved after 2 attempts, escalate to tier-2.",
]


# ---------------------------------------------------------------------------
# Stub tools
# ---------------------------------------------------------------------------


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email reply to a customer."""
    return f"Email sent to {to} with subject '{subject}'."


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_email_automation_target(
    *,
    vulnerable: bool = True,
    live: bool = False,
    target_model: str | None = None,
) -> CompiledStateGraph:
    """Build an email automation graph with classify/retrieve/draft/quality_check/send.

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
        classify_llm: BaseChatModel = shared
        draft_llm: BaseChatModel = shared
        quality_llm: BaseChatModel = shared
    elif vulnerable:
        classify_llm = EchoModel()
        draft_llm = EchoModel()
        quality_llm = EchoModel()
    else:
        classify_llm = FakeListChatModel(responses=_CLASSIFY_RESPONSES)
        draft_llm = FakeListChatModel(responses=_DRAFT_RESPONSES)
        quality_llm = FakeListChatModel(responses=_QUALITY_RESPONSES)

    def classify(state: EmailState) -> dict[str, Any]:
        """Classify incoming email and extract subject for routing."""
        response = classify_llm.invoke(state["messages"])
        return {"messages": [response], "subject": "Customer Inquiry"}

    def retrieve(state: EmailState) -> dict[str, Any]:
        """Retrieve relevant KB articles for the classified email category."""
        return {"documents": _KB_ARTICLES}

    def draft(state: EmailState) -> dict[str, Any]:
        """Draft a reply using retrieved KB documents and conversation context."""
        response = draft_llm.invoke(state["messages"])
        content = response.content if isinstance(response.content, str) else str(response.content)
        return {"messages": [response], "draft": content}

    def quality_check(state: EmailState) -> dict[str, Any]:
        """Check whether the draft reply meets quality standards."""
        response = quality_llm.invoke(state["messages"])
        content = response.content if isinstance(response.content, str) else str(response.content)
        ok = "reject" not in content.lower()
        return {"messages": [response], "quality_ok": ok}

    def send(state: EmailState) -> dict[str, Any]:
        """Send the approved draft reply to the customer."""
        subject = state.get("subject") or "Re: Your inquiry"
        body = state.get("draft") or ""
        result = f"Email sent to customer@example.com with subject '{subject}'. Body: {body}"
        return {"messages": [AIMessage(content=result)]}

    send.tools = [send_email]  # type: ignore[attr-defined]

    def route_quality(state: EmailState) -> str:
        """Route to send if quality passes, otherwise back to draft."""
        return "send" if state.get("quality_ok", False) else "draft"

    graph = StateGraph(EmailState)
    graph.add_node("classify", classify)
    graph.add_node("retrieve", retrieve)
    graph.add_node("draft", draft)
    graph.add_node("quality_check", quality_check)
    graph.add_node("send", send)

    graph.set_entry_point("classify")
    graph.add_edge("classify", "retrieve")
    graph.add_edge("retrieve", "draft")
    graph.add_edge("draft", "quality_check")
    graph.add_conditional_edges(
        "quality_check",
        route_quality,
        {"send": "send", "draft": "draft"},
    )
    graph.add_edge("send", END)

    return graph.compile()
