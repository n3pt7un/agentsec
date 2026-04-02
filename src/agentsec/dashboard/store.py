"""JSON file-based scan result persistence."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from agentsec.core.finding import FindingOverride
from agentsec.core.scanner import ScanResult
from agentsec.reporters.json_report import generate_json

logger = logging.getLogger(__name__)

_DEFAULT_DIR = Path.home() / ".agentsec" / "scans"


class ScanStore:
    """Reads and writes ScanResult JSON files to disk.

    Each scan is stored as ``{scan_id}.json`` in the base directory.
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or _DEFAULT_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save(self, scan_id: str, result: ScanResult) -> Path:
        """Persist a ScanResult to disk.

        Args:
            scan_id: Unique scan identifier (used as filename stem).
            result: The scan result to store.

        Returns:
            Path to the written file.
        """
        self.base_dir.mkdir(parents=True, exist_ok=True)
        path = self.base_dir / f"{scan_id}.json"
        path.write_text(generate_json(result))
        return path

    def load(self, scan_id: str) -> ScanResult | None:
        """Load a ScanResult from disk.

        Args:
            scan_id: The scan identifier.

        Returns:
            ScanResult if found, None otherwise.
        """
        path = self.base_dir / f"{scan_id}.json"
        if not path.exists():
            return None
        try:
            raw = json.loads(path.read_text())
            data = raw.get("scan_result", raw)
            return ScanResult.model_validate(data)
        except Exception:
            logger.warning("Failed to load scan %s", scan_id, exc_info=True)
            return None

    def list_scans(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """List scan summaries ordered by file modification time (newest first).

        Args:
            limit: Maximum number of results.
            offset: Number of results to skip.

        Returns:
            List of summary dicts with scan_id, target, timestamps, counts.
        """
        files = sorted(
            self.base_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        summaries = []
        for path in files[offset : offset + limit]:
            scan_id = path.stem
            result = self.load(scan_id)
            if result is None:
                continue
            summaries.append(
                {
                    "scan_id": scan_id,
                    "target": result.target,
                    "started_at": result.started_at.isoformat(),
                    "duration_ms": result.duration_ms,
                    "total_probes": result.total_probes,
                    "vulnerable_count": result.vulnerable_count,
                    "resistant_count": result.resistant_count,
                    "error_count": result.error_count,
                }
            )
        return summaries

    def apply_override(
        self,
        scan_id: str,
        probe_id: str,
        override: FindingOverride,
    ) -> ScanResult | None:
        """Apply an override to a finding and re-persist the scan.

        Args:
            scan_id: The scan identifier.
            probe_id: The probe ID of the finding to override.
            override: The override to apply.

        Returns:
            Updated ScanResult if found, None otherwise.
        """
        result = self.load(scan_id)
        if result is None:
            return None
        for i, finding in enumerate(result.findings):
            if finding.probe_id == probe_id:
                result.findings[i] = finding.model_copy(update={"override": override})
                self.save(scan_id, result)
                return result
        return None

    def remove_override(
        self,
        scan_id: str,
        probe_id: str,
    ) -> ScanResult | None:
        """Remove an override from a finding and re-persist the scan.

        Args:
            scan_id: The scan identifier.
            probe_id: The probe ID of the finding to clear the override from.

        Returns:
            Updated ScanResult if found and override removed, None otherwise.
        """
        result = self.load(scan_id)
        if result is None:
            return None
        for i, finding in enumerate(result.findings):
            if finding.probe_id == probe_id and finding.override is not None:
                result.findings[i] = finding.model_copy(update={"override": None})
                self.save(scan_id, result)
                return result
        return None

    def delete(self, scan_id: str) -> bool:
        """Delete a scan result file.

        Args:
            scan_id: The scan identifier.

        Returns:
            True if deleted, False if not found.
        """
        path = self.base_dir / f"{scan_id}.json"
        if not path.exists():
            return False
        path.unlink()
        return True
