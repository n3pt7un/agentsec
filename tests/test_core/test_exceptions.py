"""Tests for the custom exception hierarchy."""

from agentsec.core.exceptions import (
    AgentSecError,
    LLMAuthError,
    LLMProviderError,
    LLMTransientError,
)


class TestLLMExceptions:
    def test_llm_provider_error_is_agentsec_error(self):
        assert issubclass(LLMProviderError, AgentSecError)

    def test_llm_auth_error_is_provider_error(self):
        assert issubclass(LLMAuthError, LLMProviderError)

    def test_llm_transient_error_is_provider_error(self):
        assert issubclass(LLMTransientError, LLMProviderError)

    def test_llm_provider_error_message(self):
        err = LLMProviderError("something broke")
        assert str(err) == "something broke"

    def test_llm_auth_error_caught_as_provider_error(self):
        try:
            raise LLMAuthError("bad key")
        except LLMProviderError as e:
            assert str(e) == "bad key"

    def test_llm_transient_error_caught_as_provider_error(self):
        try:
            raise LLMTransientError("rate limited")
        except LLMProviderError as e:
            assert str(e) == "rate limited"
