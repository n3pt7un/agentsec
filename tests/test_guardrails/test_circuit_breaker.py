"""Tests for CircuitBreaker — three-state circuit breaker for agent nodes."""

import pytest

from agentsec.guardrails.circuit_breaker import CircuitBreaker, CircuitOpenError


class TestProtectDecorator:
    def test_closed_passes_call_through(self):
        cb = CircuitBreaker()

        @cb.protect("agent_a")
        def node(state):
            return {"result": "ok"}

        assert node({}) == {"result": "ok"}

    def test_failure_below_threshold_reraises_original(self):
        cb = CircuitBreaker(failure_threshold=3)

        @cb.protect("agent_a")
        def node(state):
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            node({})

        # one failure below threshold — state still closed
        assert cb.circuit_state("agent_a") == "closed"

    def test_trips_open_at_threshold(self):
        cb = CircuitBreaker(failure_threshold=2)

        @cb.protect("agent_a")
        def node(state):
            raise RuntimeError("fail")

        with pytest.raises(RuntimeError):
            node({})
        with pytest.raises(CircuitOpenError) as exc_info:
            node({})

        assert exc_info.value.agent_name == "agent_a"
        assert exc_info.value.failure_count == 2
        assert cb.circuit_state("agent_a") == "open"

    def test_circuit_open_error_chains_original(self):
        cb = CircuitBreaker(failure_threshold=1)

        @cb.protect("a")
        def node(state):
            raise ValueError("root cause")

        with pytest.raises(CircuitOpenError) as exc_info:
            node({})

        assert isinstance(exc_info.value.__cause__, ValueError)

    def test_open_returns_fallback_without_calling_node(self):
        cb = CircuitBreaker(failure_threshold=1, fallback_message="unavailable")
        calls = []

        @cb.protect("a")
        def node(state):
            calls.append(1)
            raise RuntimeError("fail")

        with pytest.raises(CircuitOpenError):
            node({})

        # second call — circuit is open, node should NOT be called
        result = node({})
        assert len(calls) == 1  # only the first (tripping) call
        assert result["messages"][0].content == "unavailable"
        assert result["messages"][0].type == "ai"

    def test_open_to_half_open_after_timeout(self, monkeypatch):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=10.0)
        import time

        @cb.protect("a")
        def node(state):
            raise RuntimeError("fail")

        with pytest.raises(CircuitOpenError):
            node({})

        assert cb.circuit_state("a") == "open"

        # Advance monotonic clock past recovery_timeout
        original_monotonic = time.monotonic
        monkeypatch.setattr(time, "monotonic", lambda: original_monotonic() + 20.0)

        # Next call: circuit should transition to half_open and allow the trial
        # (node still raises, which causes circuit to re-open)
        with pytest.raises(CircuitOpenError):
            node({})

    def test_half_open_closes_on_success(self, monkeypatch):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=10.0)
        import time

        call_count = [0]

        @cb.protect("a")
        def node(state):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("first fail")
            return {"ok": True}

        with pytest.raises(CircuitOpenError):
            node({})

        original_monotonic = time.monotonic
        monkeypatch.setattr(time, "monotonic", lambda: original_monotonic() + 20.0)

        result = node({})
        assert result == {"ok": True}
        assert cb.circuit_state("a") == "closed"

    def test_half_open_reopens_on_failure(self, monkeypatch):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=10.0)
        import time

        @cb.protect("a")
        def node(state):
            raise RuntimeError("always fails")

        with pytest.raises(CircuitOpenError):
            node({})

        original_monotonic = time.monotonic
        monkeypatch.setattr(time, "monotonic", lambda: original_monotonic() + 20.0)

        with pytest.raises(CircuitOpenError):
            node({})

        assert cb.circuit_state("a") == "open"

    def test_sync_node_wrapped_correctly(self):
        cb = CircuitBreaker()

        @cb.protect("sync_agent")
        def node(state):
            return {"sync": True}

        import asyncio
        assert not asyncio.iscoroutinefunction(node)
        assert node({}) == {"sync": True}

    async def test_async_node_wrapped_correctly(self):
        cb = CircuitBreaker()

        @cb.protect("async_agent")
        async def node(state):
            return {"async": True}

        import asyncio
        assert asyncio.iscoroutinefunction(node)
        assert await node({}) == {"async": True}

    async def test_async_node_trips_circuit(self):
        cb = CircuitBreaker(failure_threshold=1)

        @cb.protect("async_a")
        async def node(state):
            raise ValueError("async fail")

        with pytest.raises(CircuitOpenError):
            await node({})

        assert cb.circuit_state("async_a") == "open"

    async def test_async_open_returns_fallback(self):
        cb = CircuitBreaker(failure_threshold=1, fallback_message="async fallback")

        @cb.protect("async_b")
        async def node(state):
            raise RuntimeError("fail")

        with pytest.raises(CircuitOpenError):
            await node({})

        result = await node({})
        assert result["messages"][0].content == "async fallback"

    def test_independent_state_per_agent_name(self):
        cb = CircuitBreaker(failure_threshold=1)

        @cb.protect("agent_x")
        def node_x(state):
            raise RuntimeError("x fails")

        @cb.protect("agent_y")
        def node_y(state):
            return {"y": "ok"}

        with pytest.raises(CircuitOpenError):
            node_x({})

        # agent_y should be unaffected
        assert node_y({}) == {"y": "ok"}
        assert cb.circuit_state("agent_y") == "closed"


class TestCircuitState:
    def test_initial_state_is_closed(self):
        cb = CircuitBreaker()

        @cb.protect("a")
        def node(state):
            return {}

        assert cb.circuit_state("a") == "closed"

    def test_state_is_open_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=1)

        @cb.protect("a")
        def node(state):
            raise RuntimeError("fail")

        with pytest.raises(CircuitOpenError):
            node({})

        assert cb.circuit_state("a") == "open"

    def test_unknown_agent_raises_key_error(self):
        cb = CircuitBreaker()
        with pytest.raises(KeyError):
            cb.circuit_state("unknown_agent")
