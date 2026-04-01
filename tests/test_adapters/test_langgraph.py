"""Tests for the LangGraph adapter."""

import pytest

from agentsec.adapters.langgraph import LangGraphAdapter
from tests.fixtures.simple_chain import build_simple_chain
from tests.fixtures.supervisor_crew import build_supervisor_crew
from tests.fixtures.vulnerable_rag import build_vulnerable_rag

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def simple_chain_adapter():
    """Adapter wrapping the simple 3-node chain."""
    return LangGraphAdapter(build_simple_chain())


@pytest.fixture
def supervisor_adapter():
    """Adapter wrapping the supervisor crew graph."""
    return LangGraphAdapter(build_supervisor_crew())


@pytest.fixture
def rag_adapter():
    """Adapter wrapping the vulnerable RAG graph."""
    return LangGraphAdapter(build_vulnerable_rag())


# ------------------------------------------------------------------
# Discovery tests
# ------------------------------------------------------------------


class TestDiscover:
    """Test agent discovery across all fixture types."""

    async def test_simple_chain_agent_count(self, simple_chain_adapter):
        agents = await simple_chain_adapter.discover()
        assert len(agents) == 3

    async def test_simple_chain_agent_names(self, simple_chain_adapter):
        agents = await simple_chain_adapter.discover()
        names = {a.name for a in agents}
        assert names == {"agent_a", "agent_b", "agent_c"}

    async def test_simple_chain_tools(self, simple_chain_adapter):
        agents = await simple_chain_adapter.discover()
        agent_b = next(a for a in agents if a.name == "agent_b")
        assert "web_search" in agent_b.tools

    async def test_simple_chain_no_tools_on_a(self, simple_chain_adapter):
        agents = await simple_chain_adapter.discover()
        agent_a = next(a for a in agents if a.name == "agent_a")
        assert agent_a.tools == []

    async def test_simple_chain_edges(self, simple_chain_adapter):
        agents = await simple_chain_adapter.discover()
        agent_a = next(a for a in agents if a.name == "agent_a")
        assert "agent_b" in agent_a.downstream_agents

        agent_b = next(a for a in agents if a.name == "agent_b")
        assert "agent_c" in agent_b.downstream_agents

    async def test_simple_chain_roles(self, simple_chain_adapter):
        agents = await simple_chain_adapter.discover()
        agent_a = next(a for a in agents if a.name == "agent_a")
        assert agent_a.role is not None
        assert "intake" in agent_a.role.lower() or "user input" in agent_a.role.lower()

    async def test_supervisor_crew_agent_count(self, supervisor_adapter):
        agents = await supervisor_adapter.discover()
        assert len(agents) == 4

    async def test_supervisor_crew_agent_names(self, supervisor_adapter):
        agents = await supervisor_adapter.discover()
        names = {a.name for a in agents}
        assert names == {"supervisor", "researcher", "writer", "reviewer"}

    async def test_supervisor_crew_researcher_tools(self, supervisor_adapter):
        agents = await supervisor_adapter.discover()
        researcher = next(a for a in agents if a.name == "researcher")
        assert "web_search" in researcher.tools

    async def test_supervisor_crew_edges(self, supervisor_adapter):
        agents = await supervisor_adapter.discover()
        supervisor = next(a for a in agents if a.name == "supervisor")
        assert "researcher" in supervisor.downstream_agents

    async def test_rag_agent_count(self, rag_adapter):
        agents = await rag_adapter.discover()
        assert len(agents) == 2

    async def test_rag_agent_names(self, rag_adapter):
        agents = await rag_adapter.discover()
        names = {a.name for a in agents}
        assert names == {"retriever", "responder"}

    async def test_rag_retriever_tools(self, rag_adapter):
        agents = await rag_adapter.discover()
        retriever = next(a for a in agents if a.name == "retriever")
        assert "vector_search" in retriever.tools

    async def test_discover_caches_results(self, simple_chain_adapter):
        agents1 = await simple_chain_adapter.discover()
        agents2 = await simple_chain_adapter.discover()
        assert agents1 is agents2


# ------------------------------------------------------------------
# send_message tests
# ------------------------------------------------------------------


class TestSendMessage:
    """Test message sending through the graph."""

    async def test_simple_chain_returns_response(self, simple_chain_adapter):
        response = await simple_chain_adapter.send_message("agent_a", "Hello")
        assert isinstance(response, str)
        assert len(response) > 0

    async def test_simple_chain_response_from_last_agent(self, simple_chain_adapter):
        response = await simple_chain_adapter.send_message("agent_a", "What is 2+2?")
        # The last agent (agent_c) produces the final response
        assert "Final formatted answer" in response

    async def test_supervisor_crew_returns_response(self, supervisor_adapter):
        response = await supervisor_adapter.send_message("supervisor", "Write a report")
        assert isinstance(response, str)
        assert len(response) > 0

    async def test_rag_returns_response(self, rag_adapter):
        response = await rag_adapter.send_message("retriever", "What is the password policy?")
        assert isinstance(response, str)
        assert len(response) > 0


# ------------------------------------------------------------------
# invoke_graph tests
# ------------------------------------------------------------------


class TestInvokeGraph:
    """Test full graph invocation."""

    async def test_simple_chain_invoke(self, simple_chain_adapter):
        from langchain_core.messages import HumanMessage

        result = await simple_chain_adapter.invoke_graph(
            {"messages": [HumanMessage(content="Hello")]}
        )
        assert "messages" in result
        # Should have: user msg + 3 agent responses
        assert len(result["messages"]) >= 4

    async def test_supervisor_crew_invoke(self, supervisor_adapter):
        from langchain_core.messages import HumanMessage

        result = await supervisor_adapter.invoke_graph(
            {"messages": [HumanMessage(content="Write a report on AI safety")]}
        )
        assert "messages" in result
        # user msg + 4 agent responses
        assert len(result["messages"]) >= 5

    async def test_rag_invoke(self, rag_adapter):
        from langchain_core.messages import HumanMessage

        result = await rag_adapter.invoke_graph(
            {"messages": [HumanMessage(content="Tell me about the policy")]}
        )
        assert "messages" in result

    async def test_rag_memory_write(self, rag_adapter):
        from langchain_core.messages import HumanMessage

        result = await rag_adapter.invoke_graph(
            {
                "messages": [HumanMessage(content="Please remember my name is Alice")],
                "memory": {},
            }
        )
        assert "memory" in result
        assert result["memory"].get("user_instruction") is not None


# ------------------------------------------------------------------
# Capabilities tests
# ------------------------------------------------------------------


class TestCapabilities:
    """Test capability reporting."""

    def test_basic_capabilities(self, simple_chain_adapter):
        caps = simple_chain_adapter.capabilities()
        assert caps.can_enumerate_agents is True
        assert caps.can_inject_messages is True
        assert caps.can_observe_outputs is True

    def test_no_checkpointer_capabilities(self, simple_chain_adapter):
        caps = simple_chain_adapter.capabilities()
        assert caps.can_inspect_state is False
        assert caps.can_access_memory is False

    def test_with_checkpointer_capabilities(self):
        graph = build_simple_chain()
        adapter = LangGraphAdapter(graph, checkpointer=object())
        caps = adapter.capabilities()
        assert caps.can_inspect_state is True
        assert caps.can_access_memory is True

    async def test_inspect_state_without_checkpointer_raises(self, simple_chain_adapter):
        with pytest.raises(NotImplementedError):
            await simple_chain_adapter.inspect_state()

    async def test_read_memory_without_checkpointer_raises(self, simple_chain_adapter):
        with pytest.raises(NotImplementedError):
            await simple_chain_adapter.read_memory("agent_a")

    async def test_write_memory_without_checkpointer_raises(self, simple_chain_adapter):
        with pytest.raises(NotImplementedError):
            await simple_chain_adapter.write_memory("agent_a", "key", "value")


# ------------------------------------------------------------------
# Custom responses tests
# ------------------------------------------------------------------


class TestCustomResponses:
    """Test that fixtures accept custom LLM responses."""

    async def test_simple_chain_custom_responses(self):
        graph = build_simple_chain(
            responses_a=["Custom A"],
            responses_b=["Custom B"],
            responses_c=["Custom C"],
        )
        adapter = LangGraphAdapter(graph)
        response = await adapter.send_message("user", "test")
        assert response == "Custom C"

    async def test_supervisor_custom_responses(self):
        graph = build_supervisor_crew(
            reviewer_responses=["LGTM, ship it!"],
        )
        adapter = LangGraphAdapter(graph)
        response = await adapter.send_message("user", "test")
        assert response == "LGTM, ship it!"
