"""Custom exception hierarchy for agentsec."""


class AgentSecError(Exception):
    """Root exception for all agentsec errors."""


class ProbeError(AgentSecError):
    """Raised when a probe fails unexpectedly during execution."""


class AdapterError(AgentSecError):
    """Raised by adapter operations (discovery, messaging, invocation)."""


class ConfigError(AgentSecError):
    """Raised for invalid or missing configuration."""


class RegistryError(AgentSecError):
    """Raised by the probe registry (duplicate IDs, import failures, etc.)."""
