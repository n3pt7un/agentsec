"""LangGraph adapter for agentsec — wraps a compiled StateGraph for probing."""

from __future__ import annotations

import ast
import inspect
import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph.state import CompiledStateGraph

from agentsec.adapters.base import (
    AbstractAdapter,
    AdapterCapabilities,
    AgentInfo,
)

logger = logging.getLogger(__name__)

# Sentinel nodes injected by LangGraph that are not real agents.
_INTERNAL_NODES = frozenset({"__start__", "__end__"})

_LLM_ATTR_NAMES: frozenset[str] = frozenset({"llm", "model", "chain", "agent"})


def _detect_routing_type(fn) -> str:
    """Detect whether a conditional-edge routing function makes LLM calls.

    Uses AST inspection of the function body to find Call nodes where the
    callee is an attribute access on an object whose name contains 'llm',
    'model', 'chain', or 'agent'. Keyword search on raw source text is
    intentionally avoided — comments and docstrings produce false positives.

    Returns:
        "llm"           if LLM call expressions are found in the AST
        "deterministic" if source is available but no LLM calls found
        "unknown"       if source cannot be retrieved (compiled, lambda, etc.)
    """
    try:
        source = inspect.getsource(fn)
        tree = ast.parse(source)
    except (OSError, TypeError, IndentationError):
        return "unknown"

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                obj = func.value
                while isinstance(obj, ast.Attribute):
                    if obj.attr.lower() in _LLM_ATTR_NAMES:
                        return "llm"
                    obj = obj.value
                if isinstance(obj, ast.Name) and obj.id.lower() in _LLM_ATTR_NAMES:
                    return "llm"

    return "deterministic"


class LangGraphAdapter(AbstractAdapter):
    """Adapter that wraps a compiled LangGraph StateGraph.

    Inspects the graph topology to enumerate agents, and delegates
    message sending / invocation to the compiled graph.
    """

    def __init__(
        self,
        graph: CompiledStateGraph,
        *,
        entry_key: str = "messages",
        checkpointer: Any | None = None,
    ) -> None:
        """Initialise the adapter.

        Args:
            graph: A compiled LangGraph StateGraph.
            entry_key: The state key where user messages are inserted.
            checkpointer: Optional LangGraph checkpointer for memory probes.
        """
        self.graph = graph
        self.entry_key = entry_key
        self.checkpointer = checkpointer
        self._agents: list[AgentInfo] | None = None

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def discover(self) -> list[AgentInfo]:
        """Extract agents from the compiled graph's node definitions.

        Inspects ``graph.get_graph()`` for nodes and edges, and the
        builder's node specs for docstrings and bound tools.
        """
        if self._agents is not None:
            return self._agents

        graph_view = self.graph.get_graph()

        # Collect nodes directly reachable from __start__
        entry_point_names: set[str] = {
            e.target
            for e in graph_view.edges
            if e.source == "__start__" and e.target not in _INTERNAL_NODES
        }

        # Build edge map: source -> list[target]
        edge_map: dict[str, list[str]] = {}
        for edge in graph_view.edges:
            src, tgt = edge.source, edge.target
            if src in _INTERNAL_NODES or tgt in _INTERNAL_NODES:
                continue
            edge_map.setdefault(src, []).append(tgt)

        # Access builder node specs for richer metadata
        builder_nodes: dict[str, Any] = {}
        if hasattr(self.graph, "builder") and hasattr(self.graph.builder, "nodes"):
            builder_nodes = self.graph.builder.nodes

        agents: list[AgentInfo] = []
        for node_id in graph_view.nodes:
            if node_id in _INTERNAL_NODES:
                continue

            tools: list[str] = []
            role: str | None = None

            # Try to extract metadata from builder spec
            spec = builder_nodes.get(node_id)
            if spec is not None:
                runnable = getattr(spec, "runnable", None)
                func = getattr(runnable, "func", None)
                if func is not None and func.__doc__:
                    role = func.__doc__.strip().split("\n")[0]

                # Detect tools attached to the node function
                tools = _extract_tools(func)

            agents.append(
                AgentInfo(
                    name=node_id,
                    role=role,
                    tools=tools,
                    downstream_agents=edge_map.get(node_id, []),
                    is_entry_point=node_id in entry_point_names,
                )
            )

        self._agents = agents

        # Populate routing_type for nodes that have conditional edges
        if hasattr(self.graph, "builder") and hasattr(self.graph.builder, "branches"):
            for node_name, branch_dict in self.graph.builder.branches.items():
                for branch_spec in branch_dict.values():
                    fn = getattr(branch_spec.path, "func", branch_spec.path)
                    rtype = _detect_routing_type(fn)
                    for agent in self._agents:
                        if agent.name == node_name:
                            agent.routing_type = rtype
                            break

        return agents

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    async def send_message(self, agent: str, content: str) -> str:
        """Send a message through the graph and return the final text response.

        The message is injected at the graph entry point.  LangGraph does not
        natively support targeting an individual node mid-graph, so this
        invokes the full graph with the given content and returns the last
        AI message.
        """
        result = await self.graph.ainvoke(
            {self.entry_key: [HumanMessage(content=content)]},
        )
        return _extract_last_ai_text(result.get(self.entry_key, []))

    async def invoke_graph(self, input_data: dict) -> dict:
        """Run the full graph end-to-end and return the final state."""
        return await self.graph.ainvoke(input_data)

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    def capabilities(self) -> AdapterCapabilities:
        """Report what this adapter supports."""
        has_checkpointer = self.checkpointer is not None
        return AdapterCapabilities(
            can_enumerate_agents=True,
            can_inject_messages=True,
            can_observe_outputs=True,
            can_inspect_state=has_checkpointer,
            can_intercept_handoffs=False,
            can_access_memory=has_checkpointer,
        )

    # ------------------------------------------------------------------
    # Optional: state / memory (require checkpointer)
    # ------------------------------------------------------------------

    async def inspect_state(self) -> dict:
        """Inspect the current graph state via the checkpointer."""
        if self.checkpointer is None:
            raise NotImplementedError("No checkpointer configured — cannot inspect state")
        state = await self.graph.aget_state({"configurable": {"thread_id": "default"}})
        return state.values if hasattr(state, "values") else {}

    async def read_memory(self, agent: str) -> dict:
        """Read memory by retrieving the full checkpoint state."""
        if self.checkpointer is None:
            raise NotImplementedError("No checkpointer configured — cannot read memory")
        state = await self.graph.aget_state({"configurable": {"thread_id": "default"}})
        values = state.values if hasattr(state, "values") else {}
        return {"agent": agent, "state": values}

    async def write_memory(self, agent: str, key: str, value: str | dict[str, str]) -> None:
        """Write a key into the graph state via update_state.

        Args:
            agent: Name of the target agent (informational; not used for routing).
            key: Top-level state key to write (e.g. ``"memory"``).
            value: String or dict value to store at ``key``.
        """
        if self.checkpointer is None:
            raise NotImplementedError("No checkpointer configured — cannot write memory")
        await self.graph.aupdate_state(
            {"configurable": {"thread_id": "default"}},
            {key: value},
        )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _extract_tools(func: Any) -> list[str]:
    """Try to discover tool names attached to a node function.

    Checks for a ``tools`` attribute (common pattern when tools are
    bound to the function or stored as a list on it).
    """
    tools: list[str] = []
    tool_list = getattr(func, "tools", None)
    if tool_list and isinstance(tool_list, (list, tuple)):
        for t in tool_list:
            name = getattr(t, "name", None) or str(t)
            tools.append(name)
    return tools


def _extract_last_ai_text(messages: list) -> str:
    """Return the text content of the last AIMessage in a message list."""
    for msg in reversed(messages):
        if isinstance(msg, AIMessage):
            return msg.content if isinstance(msg.content, str) else str(msg.content)
    return ""
