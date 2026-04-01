"""Base class and metadata model for all agentsec probes."""

from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

from agentsec.core.finding import Finding, OWASPCategory, Remediation, Severity


class ProbeMetadata(BaseModel):
    """Static metadata about a probe."""

    id: str  # e.g. "ASI01-INDIRECT-INJECT"
    name: str  # e.g. "Indirect Prompt Injection via Tool Output"
    category: OWASPCategory
    default_severity: Severity
    description: str  # What this probe tests
    tags: list[str] = Field(default_factory=list)


class BaseProbe(ABC):
    """Base class for all attack probes.

    Each probe encapsulates a single attack strategy, its metadata, and
    its remediation guidance. Probes are self-contained and never depend
    on other probes.
    """

    @abstractmethod
    def metadata(self) -> ProbeMetadata:
        """Return static probe metadata."""
        ...

    @abstractmethod
    async def attack(self, adapter) -> Finding:
        """Execute the probe against a target system via the adapter.

        Args:
            adapter: An adapter instance (LangGraph, Protocol, etc.)

        Returns:
            Finding with status, evidence, and remediation.
        """
        ...

    @abstractmethod
    def remediation(self) -> Remediation:
        """Return the default remediation for this probe's vulnerability class."""
        ...
