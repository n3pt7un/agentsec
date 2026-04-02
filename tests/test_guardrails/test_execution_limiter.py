"""Tests for ExecutionLimiter — enforces per-agent step/time/token limits."""

import time

import pytest

from agentsec.guardrails.execution_limiter import (
    ExecutionLimiter,
    ExecutionLimitExceededError,
)


class TestExecutionLimitExceeded:
    def test_attributes_populated(self):
        exc = ExecutionLimitExceededError(
            agent_name="my_agent",
            limit_type="steps",
            value=10,
            limit=10,
        )
        assert exc.agent_name == "my_agent"
        assert exc.limit_type == "steps"
        assert exc.value == 10
        assert exc.limit == 10
        assert "my_agent" in str(exc)
        assert "steps" in str(exc)


class TestEnforceDecorator:
    # --- steps ---

    def test_steps_limit_raises_when_exceeded(self):
        limiter = ExecutionLimiter(max_steps=2)

        @limiter.enforce("a")
        def node(state):
            return {}

        node({})
        node({})
        with pytest.raises(ExecutionLimitExceededError) as exc_info:
            node({})

        assert exc_info.value.limit_type == "steps"
        assert exc_info.value.agent_name == "a"
        assert exc_info.value.limit == 2

    def test_steps_not_raised_below_limit(self):
        limiter = ExecutionLimiter(max_steps=3)

        @limiter.enforce("a")
        def node(state):
            return {}

        for _ in range(3):
            node({})  # should not raise

    def test_steps_accumulate_across_calls(self):
        limiter = ExecutionLimiter(max_steps=5)
        count = [0]

        @limiter.enforce("a")
        def node(state):
            count[0] += 1
            return {}

        for _ in range(5):
            node({})
        assert count[0] == 5

    # --- seconds ---

    def test_seconds_limit_raises_when_exceeded(self, monkeypatch):
        limiter = ExecutionLimiter(max_seconds=1.0)
        original_monotonic = time.monotonic

        @limiter.enforce("a")
        def node(state):
            return {}

        node({})  # sets started_at

        # Advance clock 2 seconds past started_at
        monkeypatch.setattr(time, "monotonic", lambda: original_monotonic() + 2.0)

        with pytest.raises(ExecutionLimitExceededError) as exc_info:
            node({})

        assert exc_info.value.limit_type == "seconds"
        assert exc_info.value.limit == 1.0

    def test_seconds_not_checked_on_first_call(self):
        limiter = ExecutionLimiter(max_seconds=0.001)  # absurdly small

        @limiter.enforce("a")
        def node(state):
            return {}

        # first call should not raise (started_at is None before it runs)
        node({})

    # --- tokens ---

    def test_tokens_limit_raises_when_exceeded(self):
        limiter = ExecutionLimiter(max_tokens=10)

        @limiter.enforce("a")
        def node(state):
            return {"token_usage": 6}

        node({})  # 6 tokens — under limit
        with pytest.raises(ExecutionLimitExceededError) as exc_info:
            node({})  # cumulative 12 — over limit

        assert exc_info.value.limit_type == "tokens"
        assert exc_info.value.limit == 10

    def test_tokens_ignored_when_key_absent(self):
        limiter = ExecutionLimiter(max_tokens=5)

        @limiter.enforce("a")
        def node(state):
            return {"result": "no token_usage key"}

        for _ in range(10):
            node({})  # should not raise

    def test_token_usage_accumulates_across_calls(self):
        limiter = ExecutionLimiter(max_tokens=100)

        @limiter.enforce("a")
        def node(state):
            return {"token_usage": 10}

        for _ in range(6):
            node({})  # 6 * 10 = 60 tokens, still under 100

    # --- None limits (no-op) ---

    def test_none_limits_are_noop(self):
        limiter = ExecutionLimiter()  # all None

        @limiter.enforce("a")
        def node(state):
            return {"token_usage": 9999}

        for _ in range(20):
            node({})  # should never raise

    # --- reset ---

    def test_reset_clears_steps(self):
        limiter = ExecutionLimiter(max_steps=2)

        @limiter.enforce("a")
        def node(state):
            return {}

        node({})
        node({})
        limiter.reset("a")
        node({})  # should not raise after reset

    def test_reset_unknown_agent_raises_key_error(self):
        limiter = ExecutionLimiter()
        with pytest.raises(KeyError):
            limiter.reset("never_seen")

    # --- sync / async dispatch ---

    def test_sync_node_is_not_coroutine(self):
        limiter = ExecutionLimiter()
        import asyncio

        @limiter.enforce("s")
        def node(state):
            return {}

        assert not asyncio.iscoroutinefunction(node)

    async def test_async_node_is_coroutine(self):
        limiter = ExecutionLimiter()
        import asyncio

        @limiter.enforce("a")
        async def node(state):
            return {}

        assert asyncio.iscoroutinefunction(node)
        assert await node({}) == {}

    async def test_async_steps_limit_raises(self):
        limiter = ExecutionLimiter(max_steps=1)

        @limiter.enforce("a")
        async def node(state):
            return {}

        await node({})
        with pytest.raises(ExecutionLimitExceededError):
            await node({})
