"""Probe registry — auto-discovers and manages BaseProbe subclasses."""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from pathlib import Path

from agentsec.core.exceptions import RegistryError
from agentsec.core.probe_base import BaseProbe, ProbeMetadata

logger = logging.getLogger(__name__)


class ProbeRegistry:
    """Discovers and manages available probes.

    Probes are auto-discovered by scanning subdirectories of the ``probes/``
    package whose names start with ``asi``.  Each Python module inside those
    directories is imported and inspected for ``BaseProbe`` subclasses, which
    are registered by their probe ID.
    """

    def __init__(self) -> None:
        self._probes: dict[str, type[BaseProbe]] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, probe_cls: type[BaseProbe]) -> None:
        """Register a probe class.

        Args:
            probe_cls: A concrete subclass of BaseProbe.

        Raises:
            RegistryError: If a different class is already registered under the same ID.
        """
        probe_id = probe_cls().metadata().id
        existing = self._probes.get(probe_id)
        if existing is not None and existing is not probe_cls:
            raise RegistryError(
                f"Probe ID '{probe_id}' is already registered by {existing.__qualname__}. "
                f"Cannot register {probe_cls.__qualname__} under the same ID."
            )
        self._probes[probe_id] = probe_cls
        logger.debug("Registered probe %s (%s)", probe_id, probe_cls.__qualname__)

    def discover_probes(self) -> None:
        """Scan probes/ subdirectories for BaseProbe subclasses.

        Walks all ``asi*`` subdirectories of the probes package, imports every
        Python module found there, and registers any ``BaseProbe`` subclass
        whose ``__module__`` matches the imported module (avoids re-registering
        probes imported from elsewhere).
        """
        probes_pkg_path = Path(__file__).parent

        for entry in sorted(probes_pkg_path.iterdir()):
            if not entry.is_dir() or not entry.name.startswith("asi"):
                continue

            pkg_name = f"agentsec.probes.{entry.name}"

            for module_info in pkgutil.iter_modules([str(entry)]):
                full_module_name = f"{pkg_name}.{module_info.name}"
                try:
                    module = importlib.import_module(full_module_name)
                except Exception as exc:
                    logger.warning("Could not import %s: %s", full_module_name, exc)
                    continue

                for _, cls in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(cls, BaseProbe)
                        and cls is not BaseProbe
                        and cls.__module__ == full_module_name
                    ):
                        try:
                            self.register(cls)
                        except RegistryError as exc:
                            logger.warning("Skipping probe: %s", exc)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, probe_id: str) -> type[BaseProbe] | None:
        """Return the probe class for the given probe ID, or None if not found."""
        return self._probes.get(probe_id)

    def probe_classes(self) -> list[type[BaseProbe]]:
        """Return all registered probe classes."""
        return list(self._probes.values())

    def list_all(self) -> list[ProbeMetadata]:
        """Return metadata for all registered probes."""
        return [cls().metadata() for cls in self._probes.values()]

    def __len__(self) -> int:
        return len(self._probes)

    def __contains__(self, probe_id: str) -> bool:
        return probe_id in self._probes
