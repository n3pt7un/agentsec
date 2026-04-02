"""CircuitBreaker — prevents cascading failures in agent pipelines."""

from __future__ import annotations

import asyncio
import functools
import time

from agentsec.core.exceptions import AgentSecError

_CLOSED = "closed"
_OPEN = "open"
_HALF_OPEN = "half_open"


class CircuitOpenError(AgentSecError):
    """Raised when a circuit breaker trips open.

    Attributes:
        agent_name: The agent whose circuit tripped.
        failure_count: Number of failures that caused the trip.
    """

    def __init__(self, agent_name: str, failure_count: int) -> None:
        self.agent_name = agent_name
        self.failure_count = failure_count
        super().__init__(
            f"Circuit opened for {agent_name!r} after {failure_count} failure(s)"
        )


class _FallbackMsg:
    """Minimal AI-like message returned when circuit is open."""

    type = "ai"

    def __init__(self, content: str) -> None:
        self.content = content


class CircuitBreaker:
    """Prevents cascading failures by opening after repeated agent errors.

    Implements the standard three-state circuit breaker pattern:
    CLOSED (normal) → OPEN (tripped, returns fallback) → HALF_OPEN (trial) → CLOSED

    Args:
        failure_threshold: Consecutive failures before opening the circuit.
            Defaults to 3.
        recovery_timeout: Seconds to wait in OPEN state before allowing a
            trial call (HALF_OPEN transition). Defaults to 60.0.
        fallback_message: Content returned in the ``messages`` list when the
            circuit is open. Defaults to a generic unavailability message.

    Example:
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=30.0)

        @cb.protect("my_agent")
        def my_agent_node(state: dict) -> dict:
            ...
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 60.0,
        fallback_message: str = "Service temporarily unavailable. Please try again later.",
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.fallback_message = fallback_message
        self._agents: dict[str, dict] = {}

    def _get_state(self, agent_name: str) -> dict:
        if agent_name not in self._agents:
            self._agents[agent_name] = {
                "state": _CLOSED,
                "failure_count": 0,
                "opened_at": None,
            }
        return self._agents[agent_name]

    def circuit_state(self, agent_name: str) -> str:
        """Return the current circuit state for agent_name.

        Args:
            agent_name: The name passed to protect().

        Returns:
            One of ``"closed"``, ``"open"``, or ``"half_open"``.

        Raises:
            KeyError: If agent_name has never been registered via protect().
        """
        if agent_name not in self._agents:
            raise KeyError(agent_name)
        return self._agents[agent_name]["state"]

    def _fallback_result(self) -> dict:
        return {"messages": [_FallbackMsg(self.fallback_message)]}

    def _maybe_recover(self, entry: dict) -> bool:
        """Return True if the circuit should transition OPEN → HALF_OPEN."""
        return (
            entry["opened_at"] is not None
            and time.monotonic() - entry["opened_at"] >= self.recovery_timeout
        )

    def _on_success(self, entry: dict) -> None:
        entry["failure_count"] = 0
        entry["state"] = _CLOSED

    def _on_failure(self, entry: dict, exc: Exception, agent_name: str) -> None:
        entry["failure_count"] += 1
        if entry["failure_count"] >= self.failure_threshold:
            entry["state"] = _OPEN
            entry["opened_at"] = time.monotonic()
            raise CircuitOpenError(agent_name, entry["failure_count"]) from exc
        raise exc

    def protect(self, agent_name: str):
        """Decorator factory that wraps a LangGraph node with circuit breaker logic.

        When the circuit is OPEN, the node is not called and a fallback AI
        message is returned immediately.  When the circuit trips (failure count
        reaches ``failure_threshold``), ``CircuitOpenError`` is raised with the
        original exception chained as ``__cause__``.

        Args:
            agent_name: Identifier for the agent — state tracked independently
                per name.

        Returns:
            A decorator that wraps sync or async node functions.
        """

        def decorator(func):
            entry = self._get_state(agent_name)

            if asyncio.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(state, *args, **kwargs):
                    if entry["state"] == _OPEN:
                        if self._maybe_recover(entry):
                            entry["state"] = _HALF_OPEN
                        else:
                            return self._fallback_result()
                    try:
                        result = await func(state, *args, **kwargs)
                    except Exception as exc:
                        self._on_failure(entry, exc, agent_name)
                        raise  # pragma: no cover — _on_failure always raises
                    self._on_success(entry)
                    return result

                return async_wrapper

            else:

                @functools.wraps(func)
                def sync_wrapper(state, *args, **kwargs):
                    if entry["state"] == _OPEN:
                        if self._maybe_recover(entry):
                            entry["state"] = _HALF_OPEN
                        else:
                            return self._fallback_result()
                    try:
                        result = func(state, *args, **kwargs)
                    except Exception as exc:
                        self._on_failure(entry, exc, agent_name)
                        raise  # pragma: no cover — _on_failure always raises
                    self._on_success(entry)
                    return result

                return sync_wrapper

        return decorator
