"""CredentialIsolator — redacts credential patterns from agent output."""

from __future__ import annotations

import functools
import re

_DEFAULT_PATTERNS: list[tuple[str, str]] = [
    (r"sk-[A-Za-z0-9_-]{16,}", "[REDACTED:API_KEY]"),
    (r"ghp_[A-Za-z0-9_]{16,}", "[REDACTED:GITHUB_TOKEN]"),
    (r"Bearer\s+[A-Za-z0-9_\-]{16,}", "Bearer [REDACTED]"),
    (r"(?i)(api[_-]?key|secret|password)\s*[=:]\s*\S+", r"\1=[REDACTED]"),
]


class CredentialIsolator:
    """Prevents credential leakage in agent context and output.

    Scans strings for credential-like patterns and redacts them. Designed as
    a defence-in-depth layer for agent output — complements (does not replace)
    architectural patterns like credential vaults.

    Args:
        extra_patterns: Additional (regex_str, replacement) tuples appended to
            the defaults. Compiled at init time.

    Example:
        isolator = CredentialIsolator()
        safe_output = isolator.redact(agent_response)
    """

    def __init__(
        self, extra_patterns: list[tuple[str, str]] | None = None
    ) -> None:
        all_patterns = _DEFAULT_PATTERNS + (extra_patterns or [])
        self._patterns: list[tuple[re.Pattern[str], str]] = [
            (re.compile(p), r) for p, r in all_patterns
        ]

    def redact(self, content: str) -> str:
        """Redact credential patterns from content.

        Applies all patterns in order. Returns the redacted string.

        Args:
            content: String to scan and redact.

        Returns:
            String with credentials replaced by redaction placeholders.
        """
        result = content
        for pattern, replacement in self._patterns:
            result = pattern.sub(replacement, result)
        return result

    def contains_credentials(self, content: str) -> bool:
        """Check if content contains credential-like patterns.

        Does not modify content.

        Args:
            content: String to check.

        Returns:
            True if any pattern matches, False otherwise.
        """
        return any(pattern.search(content) for pattern, _ in self._patterns)

    def filter_output(self, func):
        """Decorator that redacts credentials from node output messages.

        Calls the wrapped LangGraph node, then redacts credentials from any
        message with type == "ai" in result["messages"]. Other state keys and
        non-AI messages pass through unchanged. If the result has no "messages"
        key, returns result unchanged.

        Args:
            func: A LangGraph node function (state: dict) -> dict.

        Returns:
            Wrapped function.
        """

        @functools.wraps(func)
        def wrapper(state: dict, *args, **kwargs):
            result = func(state, *args, **kwargs)
            if not isinstance(result, dict):
                return result
            messages = result.get("messages")
            if not messages:
                return result
            new_messages = []
            for msg in messages:
                if getattr(msg, "type", None) == "ai":
                    new_messages.append(
                        msg.__class__(content=self.redact(msg.content))
                    )
                else:
                    new_messages.append(msg)
            return {**result, "messages": new_messages}

        return wrapper
