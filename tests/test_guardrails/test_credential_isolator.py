"""Tests for CredentialIsolator — redacts credentials from agent output."""

from agentsec.guardrails.credential_isolator import CredentialIsolator


class _AIMsg:
    type = "ai"

    def __init__(self, content: str) -> None:
        self.content = content


class _HumanMsg:
    type = "human"

    def __init__(self, content: str) -> None:
        self.content = content


class TestRedact:
    def test_redacts_openai_style_key(self):
        isolator = CredentialIsolator()
        result = isolator.redact("Use key sk-abcdefghijklmnopqrstuvwx to authenticate")
        assert "sk-abcdefghijklmnopqrstuvwx" not in result
        assert "[REDACTED:API_KEY]" in result

    def test_redacts_github_token(self):
        isolator = CredentialIsolator()
        result = isolator.redact("token: ghp_abcdefghijklmnopqrstuvwxyz1234")
        assert "ghp_abcdefghijklmnopqrstuvwxyz1234" not in result
        assert "[REDACTED:GITHUB_TOKEN]" in result

    def test_redacts_bearer_token(self):
        isolator = CredentialIsolator()
        result = isolator.redact("Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
        assert "abcdefghijklmnopqrstuvwxyz" not in result
        assert "Bearer [REDACTED]" in result

    def test_redacts_api_key_assignment(self):
        isolator = CredentialIsolator()
        result = isolator.redact("api_key=supersecretvalue123")
        assert "supersecretvalue123" not in result
        assert "[REDACTED]" in result

    def test_redacts_password_assignment(self):
        isolator = CredentialIsolator()
        result = isolator.redact("password=hunter2abc")
        assert "hunter2abc" not in result
        assert "[REDACTED]" in result

    def test_clean_content_passes_through_unchanged(self):
        isolator = CredentialIsolator()
        content = "Here is the weather forecast for today."
        assert isolator.redact(content) == content

    def test_empty_string(self):
        isolator = CredentialIsolator()
        assert isolator.redact("") == ""

    def test_extra_patterns_applied(self):
        isolator = CredentialIsolator(
            extra_patterns=[(r"MY_SECRET_\w+", "[REDACTED:CUSTOM]")]
        )
        result = isolator.redact("token is MY_SECRET_abc123")
        assert "MY_SECRET_abc123" not in result
        assert "[REDACTED:CUSTOM]" in result

    def test_extra_patterns_alongside_defaults(self):
        isolator = CredentialIsolator(
            extra_patterns=[(r"MY_SECRET_\w+", "[REDACTED:CUSTOM]")]
        )
        result = isolator.redact("sk-abcdefghijklmnopqr and MY_SECRET_xyz")
        assert "[REDACTED:API_KEY]" in result
        assert "[REDACTED:CUSTOM]" in result


class TestContainsCredentials:
    def test_true_for_openai_key(self):
        isolator = CredentialIsolator()
        assert isolator.contains_credentials("key: sk-abcdefghijklmnopqrstuvwx")

    def test_true_for_github_token(self):
        isolator = CredentialIsolator()
        assert isolator.contains_credentials("ghp_abcdefghijklmnopqrstuvwxyz1234")

    def test_true_for_bearer_token(self):
        isolator = CredentialIsolator()
        assert isolator.contains_credentials("Bearer abcdefghijklmnopqrstuvwxyz")

    def test_true_for_api_key_assignment(self):
        isolator = CredentialIsolator()
        assert isolator.contains_credentials("api_key=somevalue123")

    def test_false_for_clean_content(self):
        isolator = CredentialIsolator()
        assert not isolator.contains_credentials("The answer is 42.")

    def test_does_not_modify_content(self):
        isolator = CredentialIsolator()
        content = "sk-abcdefghijklmnopqrstuvwx"
        isolator.contains_credentials(content)
        assert content == "sk-abcdefghijklmnopqrstuvwx"


class TestFilterOutputDecorator:
    def test_redacts_ai_message_content(self):
        isolator = CredentialIsolator()

        @isolator.filter_output
        def node(state):
            return {"messages": [_AIMsg("Here is the key: sk-abcdefghijklmnopqrstuvwx")]}

        result = node({})
        assert "sk-abcdefghijklmnopqrstuvwx" not in result["messages"][0].content
        assert "[REDACTED:API_KEY]" in result["messages"][0].content

    def test_does_not_modify_human_messages(self):
        isolator = CredentialIsolator()

        @isolator.filter_output
        def node(state):
            return {
                "messages": [
                    _HumanMsg("my secret is sk-abcdefghijklmnopqrstuvwx"),
                    _AIMsg("clean response"),
                ]
            }

        result = node({})
        # human message content is unchanged
        assert "sk-abcdefghijklmnopqrstuvwx" in result["messages"][0].content

    def test_other_state_keys_pass_through(self):
        isolator = CredentialIsolator()

        @isolator.filter_output
        def node(state):
            return {"messages": [_AIMsg("clean")], "metadata": {"step": 1}}

        result = node({})
        assert result["metadata"] == {"step": 1}

    def test_no_messages_key_passes_through(self):
        isolator = CredentialIsolator()

        @isolator.filter_output
        def node(state):
            return {"status": "ok"}

        result = node({})
        assert result == {"status": "ok"}

    def test_multiple_ai_messages_all_redacted(self):
        isolator = CredentialIsolator()

        @isolator.filter_output
        def node(state):
            return {
                "messages": [
                    _AIMsg("key1: sk-aaaaaaaaaaaaaaaaaaaaaaaaa"),
                    _AIMsg("key2: ghp_bbbbbbbbbbbbbbbbbbbbbbbbb"),
                ]
            }

        result = node({})
        assert "[REDACTED:API_KEY]" in result["messages"][0].content
        assert "[REDACTED:GITHUB_TOKEN]" in result["messages"][1].content
