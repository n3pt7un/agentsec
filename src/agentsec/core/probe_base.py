"""Base class and metadata model for all agentsec probes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from agentsec.core.finding import Finding, OWASPCategory, Remediation, Severity

if TYPE_CHECKING:
    from agentsec.llm.detection import DetectionType
    from agentsec.llm.provider import LLMProvider


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
    async def attack(self, adapter, provider=None) -> Finding:
        """Execute the probe against a target system via the adapter.

        Args:
            adapter: An adapter instance (LangGraph, Protocol, etc.)
            provider: Optional LLMProvider for smart payload generation.

        Returns:
            Finding with status, evidence, and remediation.
        """
        ...

    @abstractmethod
    def remediation(self) -> Remediation:
        """Return the default remediation for this probe's vulnerability class."""
        ...

    async def _run_detection(
        self,
        fast_vulnerable: bool,
        provider: LLMProvider | None,
        response: str,
        detection_type: DetectionType,
        **detection_context,
    ) -> tuple[bool, str | None]:
        """Two-stage vulnerability detection.

        Stage 1 (fast): if fast_vulnerable is True, return immediately —
        the probe's own marker/regex check already confirmed vulnerability.

        Stage 2 (LLM): if fast check missed and a provider is available,
        call VulnerabilityDetector.detect() for semantic analysis.

        Stage 3 (fallback): return not-vulnerable if no provider or LLM
        also returns not-vulnerable.

        Args:
            fast_vulnerable: Result of the probe's own fast check (marker
                in response, regex match, etc.).
            provider: Optional LLM provider. If None, LLM stage is skipped.
            response: Agent response text passed to the LLM for analysis.
            detection_type: Which semantic check to run.
            **detection_context: Extra fields for the LLM prompt (e.g.
                attack_payload, original_objective, injected_role).

        Returns:
            (is_vulnerable, detection_method) where detection_method is
            "marker" | "llm" | None.
        """
        if fast_vulnerable:
            return (True, "marker")

        if provider is not None:
            from agentsec.llm.detection import VulnerabilityDetector

            result = await VulnerabilityDetector(provider).detect(
                detection_type, response, **detection_context
            )
            if result.vulnerable:
                return (True, "llm")

        return (False, None)
