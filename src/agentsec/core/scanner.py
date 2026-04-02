"""Scanner engine — orchestrates probe execution against a target adapter."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from agentsec.adapters.base import AbstractAdapter, AgentInfo
from agentsec.core.config import ScanConfig
from agentsec.core.finding import Finding, FindingStatus, Severity
from agentsec.core.pricing import load_pricing
from agentsec.llm.provider import get_provider
from agentsec.probes.registry import ProbeRegistry

logger = logging.getLogger(__name__)


class ScanResult(BaseModel):
    """Aggregated output of a full scan run."""

    target: str = ""
    findings: list[Finding] = Field(default_factory=list)
    agents_discovered: list[AgentInfo] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime
    total_probes: int = Field(description="Number of probes that were attempted")
    vulnerable_count: int = 0
    resistant_count: int = 0
    error_count: int = 0
    smart: bool = False
    detection_confidence_threshold: float = 0.8
    models_used: list[str] = Field(default_factory=list,
        description="Ordered unique list of model IDs used across all probes")
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float | None = Field(default=None,
        description="None when no pricing source is available")

    @property
    def duration_ms(self) -> int:
        """Wall-clock duration of the scan in milliseconds."""
        return int((self.finished_at - self.started_at).total_seconds() * 1000)

    @property
    def vulnerabilities(self) -> list[Finding]:
        """Findings with VULNERABLE status."""
        return [f for f in self.findings if f.status == FindingStatus.VULNERABLE]

    @property
    def critical_count(self) -> int:
        """Number of CRITICAL severity vulnerable findings."""
        return sum(1 for f in self.vulnerabilities if f.severity == Severity.CRITICAL)


# Callback signature: (probe_id, status_string, finding_or_none)
ProgressCallback = Callable[[str, str, Finding | None], None]


class Scanner:
    """Core scan orchestrator.

    Discovers probes via the registry, filters them according to the config,
    runs each probe against the adapter, and returns a ``ScanResult``.
    """

    def __init__(self, adapter: AbstractAdapter, config: ScanConfig) -> None:
        """Initialise the scanner.

        Args:
            adapter: The adapter wrapping the target agent system.
            config: Scan configuration (categories, probe IDs, timeouts, etc.).
        """
        self.adapter = adapter
        self.config = config
        self._registry = ProbeRegistry()
        self._provider = get_provider(config)

    async def run(
        self,
        *,
        target: str = "",
        progress_callback: ProgressCallback | None = None,
    ) -> ScanResult:
        """Execute all applicable probes and return a ScanResult.

        Args:
            target: Human-readable target identifier (e.g. file path).
            progress_callback: Optional callable(probe_id, status, finding) for
                live UI updates.  Called with status ``"started"`` before each
                probe and ``"completed"``/``"error"`` after.

        Returns:
            A ScanResult containing all findings.
        """
        if len(self._registry) == 0:
            self._registry.discover_probes()

        probes = [cls() for cls in self._registry.probe_classes()]

        if self.config.probes:
            allowed_ids = set(self.config.probes)
            probes = [p for p in probes if p.metadata().id in allowed_ids]

        if self.config.categories:
            allowed_cats = set(self.config.categories)
            probes = [p for p in probes if p.metadata().category.value in allowed_cats]

        # Discover agents
        agents_discovered: list[AgentInfo] = []
        try:
            agents_discovered = await self.adapter.discover()
        except Exception:
            logger.warning("Agent discovery failed", exc_info=True)

        # Validate LLM provider if smart mode is enabled
        if self.config.smart:
            await self._provider.validate()

        started_at = datetime.now(UTC)
        findings: list[Finding] = []

        for probe in probes:
            meta = probe.metadata()
            logger.info("Running probe %s", meta.id)
            if progress_callback:
                progress_callback(meta.id, "started", None)

            finding = await self._run_probe(probe)
            findings.append(finding)

            if progress_callback:
                status = "error" if finding.status == FindingStatus.ERROR else "completed"
                progress_callback(meta.id, status, finding)

            if self.config.verbose:
                logger.info("Probe %s → %s", meta.id, finding.status.value.upper())

        finished_at = datetime.now(UTC)

        # ── Aggregate LLM usage ──────────────────────────────────────
        all_usage = [u for f in findings for u in f.llm_usage]
        seen: set[str] = set()
        models_used: list[str] = []
        for u in all_usage:
            if u.model not in seen:
                seen.add(u.model)
                models_used.append(u.model)
        total_input = sum(u.input_tokens for u in all_usage)
        total_output = sum(u.output_tokens for u in all_usage)

        pricing = load_pricing(
            pricing_data=self.config.pricing_data or None,
            pricing_file=getattr(self.config, "pricing_file", None),
        )
        total_cost: float | None = pricing.compute_cost(all_usage) if pricing is not None else None

        return ScanResult(
            target=target,
            findings=findings,
            agents_discovered=agents_discovered,
            started_at=started_at,
            finished_at=finished_at,
            total_probes=len(findings),
            vulnerable_count=sum(1 for f in findings if f.status == FindingStatus.VULNERABLE),
            resistant_count=sum(1 for f in findings if f.status == FindingStatus.RESISTANT),
            error_count=sum(1 for f in findings if f.status == FindingStatus.ERROR),
            smart=self.config.smart,
            detection_confidence_threshold=self.config.detection_confidence_threshold,
            models_used=models_used,
            total_input_tokens=total_input,
            total_output_tokens=total_output,
            total_cost_usd=total_cost,
        )

    async def _run_probe(self, probe) -> Finding:
        """Run a single probe, catching timeouts and unexpected exceptions.

        Args:
            probe: An instantiated BaseProbe.

        Returns:
            A Finding.  On timeout or unexpected error the status is ERROR.
        """
        meta = probe.metadata()
        try:
            return await asyncio.wait_for(
                probe.attack(
                    self.adapter,
                    self._provider,
                    confidence_threshold=self.config.detection_confidence_threshold,
                    fallback_model=self.config.fallback_llm_model,
                ),
                timeout=self.config.timeout_per_probe,
            )
        except TimeoutError:
            logger.warning("Probe %s timed out after %ds", meta.id, self.config.timeout_per_probe)
            return self._error_finding(probe, tags=["timeout"])
        except Exception:
            logger.exception("Probe %s raised an unexpected exception", meta.id)
            return self._error_finding(probe, tags=["error"])

    @staticmethod
    def _error_finding(probe, *, tags: list[str]) -> Finding:
        """Build an ERROR Finding from probe metadata."""

        meta = probe.metadata()
        return Finding(
            probe_id=meta.id,
            probe_name=meta.name,
            category=meta.category,
            status=FindingStatus.ERROR,
            severity=meta.default_severity,
            description=meta.description,
            remediation=probe.remediation(),
            tags=tags,
        )
