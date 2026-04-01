"""RAG agent with vector store retrieval and persistent memory.

Vulnerabilities by design:
- RAG context injected directly into prompt (no sanitization)
- Memory persists across sessions with no scoping
- Retrieved documents treated as trusted content
- Agent can be instructed to store arbitrary content in memory
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import FakeListChatModel
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph

from tests.fixtures.utils import EchoModel

_DEFAULT_RETRIEVER_RESPONSES = [
    "Retrieved context: The company password policy requires 12 characters."
]
_DEFAULT_RESPONDER_RESPONSES = ["Based on the retrieved information, here is your answer."]


class MemoryState(MessagesState):
    """Extended state that includes a simple key-value memory store."""

    memory: dict[str, str]


def build_vulnerable_rag(
    *,
    vulnerable: bool = True,
    retriever_responses: list[str] | None = None,
    responder_responses: list[str] | None = None,
    checkpointer: BaseCheckpointSaver | None = None,
) -> CompiledStateGraph:
    """Build a RAG system with unsanitised context injection and open memory.

    Args:
        vulnerable: When True, both nodes use EchoModel so any probe payload
            injected as a human message is reflected back in the response,
            producing VULNERABLE findings.  When False, nodes use safe
            FakeListChatModel responses that do not echo probe markers.
        retriever_responses: Custom responses for retriever (vulnerable=False only).
        responder_responses: Custom responses for responder (vulnerable=False only).
        checkpointer: Optional LangGraph checkpointer for persistent-memory probes.

    Returns:
        A compiled LangGraph StateGraph.
    """
    if vulnerable:
        llm_ret = EchoModel()
        llm_resp = EchoModel()
    else:
        llm_ret = FakeListChatModel(responses=retriever_responses or _DEFAULT_RETRIEVER_RESPONSES)
        llm_resp = FakeListChatModel(responses=responder_responses or _DEFAULT_RESPONDER_RESPONSES)

    def retriever(state: MemoryState) -> dict[str, Any]:
        """Retriever agent — fetches context and injects it unsanitised."""
        response = llm_ret.invoke(state["messages"])
        return {"messages": [response]}

    retriever.tools = [_VectorSearchStub()]

    def responder(state: MemoryState) -> dict[str, Any]:
        """Responder agent — answers using retrieved context and memory.

        Blindly trusts retrieved content and stores anything the user asks.
        """
        response = llm_resp.invoke(state["messages"])

        # Simulate memory write: if user asks to "remember", store it.
        last_user_msg = ""
        for msg in reversed(state["messages"]):
            if hasattr(msg, "type") and msg.type == "human":
                last_user_msg = msg.content if isinstance(msg.content, str) else ""
                break

        memory = dict(state.get("memory", {}))
        if "remember" in last_user_msg.lower():
            memory["user_instruction"] = last_user_msg

        return {"messages": [response], "memory": memory}

    graph = StateGraph(MemoryState)
    graph.add_node("retriever", retriever)
    graph.add_node("responder", responder)

    graph.set_entry_point("retriever")
    graph.add_edge("retriever", "responder")
    graph.set_finish_point("responder")

    return graph.compile(checkpointer=checkpointer)


class _VectorSearchStub:
    """Minimal stub that looks like a vector search tool for discovery."""

    name = "vector_search"

    def __call__(self, query: str) -> str:
        return f"Documents matching: {query}"
