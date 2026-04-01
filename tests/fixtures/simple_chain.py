"""A → B → C linear agent chain with no security controls.

Agent A: Receives user input, passes to B
Agent B: Processes and passes to C (has a web_search tool)
Agent C: Formats final output

Vulnerabilities by design:
- No input validation between agents
- Agent B's tool has no access controls
- State is shared openly between all nodes
"""

from langchain_core.language_models import FakeListChatModel
from langgraph.graph import MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph

from tests.fixtures.utils import EchoModel

# Default responses for each agent when no custom model is supplied.
_DEFAULT_RESPONSES_A = ["I'll pass this along to the processor."]
_DEFAULT_RESPONSES_B = ["Here are the search results: [data]. Forwarding to formatter."]
_DEFAULT_RESPONSES_C = ["Final formatted answer: The answer is 42."]


def build_simple_chain(
    *,
    vulnerable: bool = True,
    responses_a: list[str] | None = None,
    responses_b: list[str] | None = None,
    responses_c: list[str] | None = None,
) -> CompiledStateGraph:
    """Build a linear 3-node chain with no security controls.

    Args:
        vulnerable: When True, all nodes use EchoModel so any probe payload
            injected as a human message is reflected back in the response,
            producing VULNERABLE findings.  When False, nodes use safe
            FakeListChatModel responses that do not echo probe markers.
        responses_a: Custom responses for agent A (only used when vulnerable=False).
        responses_b: Custom responses for agent B (only used when vulnerable=False).
        responses_c: Custom responses for agent C (only used when vulnerable=False).

    Returns:
        A compiled LangGraph StateGraph.
    """
    if vulnerable:
        llm_a = EchoModel()
        llm_b = EchoModel()
        llm_c = EchoModel()
    else:
        llm_a = FakeListChatModel(responses=responses_a or _DEFAULT_RESPONSES_A)
        llm_b = FakeListChatModel(responses=responses_b or _DEFAULT_RESPONSES_B)
        llm_c = FakeListChatModel(responses=responses_c or _DEFAULT_RESPONSES_C)

    def agent_a(state: MessagesState) -> MessagesState:
        """Intake agent — receives user input with no validation."""
        response = llm_a.invoke(state["messages"])
        return {"messages": [response]}

    def agent_b(state: MessagesState) -> MessagesState:
        """Processor agent — has a web_search tool with no access controls."""
        response = llm_b.invoke(state["messages"])
        return {"messages": [response]}

    # Attach tool metadata so the adapter can discover it.
    agent_b.tools = [_web_search_stub]

    def agent_c(state: MessagesState) -> MessagesState:
        """Formatter agent — produces final output."""
        response = llm_c.invoke(state["messages"])
        return {"messages": [response]}

    graph = StateGraph(MessagesState)
    graph.add_node("agent_a", agent_a)
    graph.add_node("agent_b", agent_b)
    graph.add_node("agent_c", agent_c)

    graph.set_entry_point("agent_a")
    graph.add_edge("agent_a", "agent_b")
    graph.add_edge("agent_b", "agent_c")
    graph.set_finish_point("agent_c")

    return graph.compile()


class _WebSearchStub:
    """Minimal stub that looks like a LangChain tool for discovery purposes."""

    name = "web_search"

    def __call__(self, query: str) -> str:
        return f"Results for: {query}"


_web_search_stub = _WebSearchStub()
