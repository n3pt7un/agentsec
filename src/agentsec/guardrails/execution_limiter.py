"""ExecutionLimiter — prevents unbounded autonomous execution in agent pipelines."""

from __future__ import annotations

import asyncio
import functools
import time

from agentsec.core.exceptions import AgentSecError


class ExecutionLimitExceededError(AgentSecError):
    """Raised when an execution limit is hit.

    Attributes:
        agent_name: The agent that exceeded a limit.
        limit_type: Which limit was hit: ``"steps"``, ``"seconds"``, or ``"tokens"``.
        value: The value that triggered the limit.
        limit: The configured limit threshold.
    """

    def __init__(
        self,
        agent_name: str,
        limit_type: str,
        value: float | int,
        limit: float | int,
    ) -> None:
        self.agent_name = agent_name
        self.limit_type = limit_type
        self.value = value
        self.limit = limit
        super().__init__(
            f"{agent_name!r} exceeded {limit_type} limit: {value} >= {limit}"
        )


class ExecutionLimiter:
    """Prevents unbounded autonomous execution by enforcing per-agent limits.

    Tracks step count, elapsed time, and token usage per named agent.
    Any combination of limits can be enabled; a limit of ``None`` is never checked.

    Args:
        max_steps: Maximum invocations before raising. ``None`` = unlimited.
        max_seconds: Maximum wall-clock seconds from first invocation.
            ``None`` = unlimited.
        max_tokens: Maximum cumulative ``token_usage`` across invocations.
            The node's return dict is checked for a ``"token_usage"`` key (int).
            ``None`` = unlimited.

    Example:
        limiter = ExecutionLimiter(max_steps=10, max_seconds=30.0)

        @limiter.enforce("my_agent")
        def my_agent_node(state: dict) -> dict:
            ...
    """

    def __init__(
        self,
        max_steps: int | None = None,
        max_seconds: float | None = None,
        max_tokens: int | None = None,
    ) -> None:
        self.max_steps = max_steps
        self.max_seconds = max_seconds
        self.max_tokens = max_tokens
        self._agents: dict[str, dict] = {}

    def _get_state(self, agent_name: str) -> dict:
        if agent_name not in self._agents:
            self._agents[agent_name] = {
                "steps": 0,
                "started_at": None,
                "tokens": 0,
            }
        return self._agents[agent_name]

    def reset(self, agent_name: str) -> None:
        """Reset all counters for agent_name to their initial state.

        Args:
            agent_name: The agent to reset.

        Raises:
            KeyError: If agent_name has never been registered via enforce().
        """
        if agent_name not in self._agents:
            raise KeyError(agent_name)
        entry = self._agents[agent_name]
        entry["steps"] = 0
        entry["started_at"] = None
        entry["tokens"] = 0

    def _check_pre(self, entry: dict, agent_name: str) -> None:
        """Check step and time limits before calling the node."""
        if self.max_steps is not None and entry["steps"] >= self.max_steps:
            raise ExecutionLimitExceededError(
                agent_name, "steps", entry["steps"], self.max_steps
            )
        if self.max_seconds is not None and entry["started_at"] is not None:
            elapsed = time.monotonic() - entry["started_at"]
            if elapsed >= self.max_seconds:
                raise ExecutionLimitExceededError(
                    agent_name, "seconds", elapsed, self.max_seconds
                )

    def _check_post(self, entry: dict, result, agent_name: str) -> None:
        """Check token limit after the node returns and accumulate token count."""
        if self.max_tokens is not None and isinstance(result, dict):
            token_usage = result.get("token_usage")
            if token_usage is not None:
                new_total = entry["tokens"] + token_usage
                if new_total >= self.max_tokens:
                    raise ExecutionLimitExceededError(
                        agent_name, "tokens", new_total, self.max_tokens
                    )
                entry["tokens"] = new_total

    def enforce(self, agent_name: str):
        """Decorator factory that enforces execution limits on a LangGraph node.

        Checks step and time limits **before** calling the node.  Checks token
        limits **after** the node returns (requires a ``"token_usage"`` key in
        the result dict).  Steps are incremented after a successful call.

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
                    self._check_pre(entry, agent_name)
                    if entry["started_at"] is None:
                        entry["started_at"] = time.monotonic()
                    result = await func(state, *args, **kwargs)
                    self._check_post(entry, result, agent_name)
                    entry["steps"] += 1
                    return result

                return async_wrapper

            else:

                @functools.wraps(func)
                def sync_wrapper(state, *args, **kwargs):
                    self._check_pre(entry, agent_name)
                    if entry["started_at"] is None:
                        entry["started_at"] = time.monotonic()
                    result = func(state, *args, **kwargs)
                    self._check_post(entry, result, agent_name)
                    entry["steps"] += 1
                    return result

                return sync_wrapper

        return decorator
