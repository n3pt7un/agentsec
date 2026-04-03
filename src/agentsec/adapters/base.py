"""Abstract adapter interface between agentsec probes and target agent systems."""

from abc import ABC, abstractmethod
from typing import Literal

from pydantic import BaseModel, Field


class AgentInfo(BaseModel):
    """Discovered agent in the target system."""

    name: str
    role: str | None = None
    tools: list[str] = Field(default_factory=list)
    downstream_agents: list[str] = Field(default_factory=list)
    is_entry_point: bool = False
    routing_type: Literal["llm", "deterministic", "unknown"] = "unknown"


class AdapterCapabilities(BaseModel):
    """What this adapter can do."""

    can_enumerate_agents: bool = True
    can_inject_messages: bool = True
    can_observe_outputs: bool = True
    can_inspect_state: bool = False
    can_intercept_handoffs: bool = False
    can_access_memory: bool = False


class AbstractAdapter(ABC):
    """Interface between agentsec probes and target agent systems.

    Probes only interact with the target system through this interface,
    ensuring probe code stays framework-agnostic.
    """

    @abstractmethod
    async def discover(self) -> list[AgentInfo]:
        """Enumerate agents, their tools, and connections."""
        ...

    @abstractmethod
    async def send_message(self, agent: str, content: str) -> str:
        """Send a message to a specific agent and return its response."""
        ...

    @abstractmethod
    async def invoke_graph(self, input_data: dict) -> dict:
        """Run the full agent graph with given input and return final output."""
        ...

    @abstractmethod
    def capabilities(self) -> AdapterCapabilities:
        """Report what this adapter supports."""
        ...

    async def inspect_state(self) -> dict:
        """Inspect current agent state (if supported).

        Raises:
            NotImplementedError: If the adapter does not support state inspection.
        """
        raise NotImplementedError("This adapter does not support state inspection")

    async def intercept_handoff(self, from_agent: str, to_agent: str, callback) -> None:
        """Intercept a handoff between agents (if supported).

        Raises:
            NotImplementedError: If the adapter does not support handoff interception.
        """
        raise NotImplementedError("This adapter does not support handoff interception")

    async def read_memory(self, agent: str) -> dict:
        """Read agent memory (if supported).

        Raises:
            NotImplementedError: If the adapter does not support memory access.
        """
        raise NotImplementedError("This adapter does not support memory access")

    async def write_memory(self, agent: str, key: str, value: str | dict[str, str]) -> None:
        """Write to agent memory (if supported).

        Args:
            agent: Name of the target agent.
            key: Top-level state key to write (e.g. ``"memory"``).
            value: Value to store — either a plain string or a dict for
                structured memory fields.

        Raises:
            NotImplementedError: If the adapter does not support memory writes.
        """
        raise NotImplementedError("This adapter does not support memory writes")
