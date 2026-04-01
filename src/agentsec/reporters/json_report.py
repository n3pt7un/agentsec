"""JSON report generator for agentsec scan results."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from agentsec import __version__
from agentsec.core.scanner import ScanResult

_SCHEMA_VERSION = "1.0.0"


def generate_json(result: ScanResult) -> str:
    """Serialize a ScanResult as pretty-printed JSON with metadata wrapper.

    Args:
        result: The scan result to serialize.

    Returns:
        A JSON string with metadata and the full scan result.
    """
    payload = {
        "metadata": {
            "agentsec_version": __version__,
            "schema_version": _SCHEMA_VERSION,
            "generated_at": datetime.now(UTC).isoformat(),
        },
        "scan_result": json.loads(result.model_dump_json()),
    }
    return json.dumps(payload, indent=2)
