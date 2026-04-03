"""SARIF 2.1.0 report generator for agentsec scan results."""

from __future__ import annotations

import json
import re

from agentsec import __version__
from agentsec.core.finding import FindingStatus, Severity
from agentsec.core.scanner import ScanResult

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/n3pt7un/agentsec"

_SEVERITY_TO_LEVEL: dict[str, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _probe_id_to_name(probe_id: str) -> str:
    """Convert a probe ID like 'ASI01-INDIRECT-INJECT' to 'Asi01IndirectInject'."""
    parts = re.split(r"[-_]", probe_id)
    return "".join(p.capitalize() for p in parts)


def generate_sarif(result: ScanResult) -> str:
    """Generate SARIF 2.1.0 JSON from a ScanResult.

    Rules cover all probes that ran (all statuses). Results cover only
    VULNERABLE and PARTIAL findings — RESISTANT findings are excluded.

    Args:
        result: The scan result to render.

    Returns:
        A SARIF 2.1.0 JSON string.
    """
    # Deduplicate rules by probe_id, preserving insertion order
    seen_ids: set[str] = set()
    rules: list[dict] = []
    for finding in result.findings:
        if finding.probe_id not in seen_ids:
            seen_ids.add(finding.probe_id)
            rules.append(
                {
                    "id": finding.probe_id,
                    "name": _probe_id_to_name(finding.probe_id),
                    "shortDescription": {"text": finding.probe_name},
                    "helpUri": _INFORMATION_URI,
                    "properties": {"tags": [finding.category.value]},
                }
            )

    # Only emit results for actionable findings
    sarif_results: list[dict] = []
    for finding in result.findings:
        if finding.status not in (FindingStatus.VULNERABLE, FindingStatus.PARTIAL):
            continue

        target_agent = (
            finding.evidence.target_agent
            if finding.evidence and finding.evidence.target_agent
            else "unknown"
        )
        message_text = finding.description
        if finding.remediation and finding.remediation.summary:
            message_text += f"\n\nRemediation: {finding.remediation.summary}"

        sarif_results.append(
            {
                "ruleId": finding.probe_id,
                "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"agent://{target_agent}"}
                        },
                        "logicalLocations": [{"name": finding.probe_id}],
                    }
                ],
            }
        )

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentsec",
                        "version": __version__,
                        "informationUri": _INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
