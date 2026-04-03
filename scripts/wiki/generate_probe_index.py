#!/usr/bin/env python3
"""Generate wiki/reference/Probe-Index.md from the probe registry."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from agentsec.probes.registry import ProbeRegistry

CATEGORY_NAMES: dict[str, str] = {
    "ASI01": "Agent Goal Hijacking",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Supply Chain Vulnerabilities",
    "ASI05": "Output & Impact Control Failures",
    "ASI06": "Memory & Context Manipulation",
    "ASI07": "Multi-Agent Orchestration Exploitation",
    "ASI08": "Uncontrolled Autonomous Execution",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agent Behavior",
}


def main() -> None:
    registry = ProbeRegistry()
    registry.discover_probes()
    all_meta = registry.list_all()

    all_meta.sort(key=lambda m: (m.category.value, m.id))

    lines: list[str] = [
        "<!-- AUTO-GENERATED — do not edit directly. Re-run scripts/wiki/generate_probe_index.py -->",
        "",
        "# Probe Index",
        "",
        f"agentsec ships {len(all_meta)} probes across all 10 OWASP Agentic categories.",
        "",
        "| Probe ID | Category | Severity | Name | Description |",
        "|----------|----------|----------|------|-------------|",
    ]

    for meta in all_meta:
        cat = meta.category.value
        cat_name = CATEGORY_NAMES.get(cat, cat)
        anchor = cat.lower() + "-" + cat_name.lower().replace(" ", "-").replace("&", "").replace("--", "-")
        cat_cell = f"[{cat}: {cat_name}](OWASP-Categories#{anchor})"
        lines.append(
            f"| `{meta.id}` | {cat_cell} | {meta.default_severity.value.upper()} "
            f"| {meta.name} | {meta.description} |"
        )

    lines += [
        "",
        "---",
        "",
        "See [OWASP Categories](OWASP-Categories) for descriptions of each category.",
    ]

    out_path = Path(__file__).parent.parent.parent / "wiki" / "Probe-Index.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n")
    print(f"Written {out_path} ({len(all_meta)} probes)")


if __name__ == "__main__":
    main()
