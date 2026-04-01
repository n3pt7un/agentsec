"""Probe registry — stub for Session 3."""

from agentsec.core.probe_base import BaseProbe, ProbeMetadata


class ProbeRegistry:
    """Discovers and manages available probes. Full implementation in Session 3."""

    def __init__(self):
        self._probes: dict[str, type[BaseProbe]] = {}

    def discover_probes(self) -> None:
        """Scan probes/ subdirectories for BaseProbe subclasses."""
        ...

    def list_all(self) -> list[ProbeMetadata]:
        """Return metadata for all registered probes."""
        return [cls().metadata() for cls in self._probes.values()]
