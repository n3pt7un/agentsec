#!/usr/bin/env python3
"""Generate wiki/reference/CLI-Commands.md from agentsec --help output."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def run_help(args: list[str]) -> str:
    """Run agentsec with given args and return stdout."""
    result = subprocess.run(
        ["uv", "run", "agentsec"] + args + ["--help"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent.parent,
    )
    return result.stdout or result.stderr


def parse_flags(help_text: str) -> list[tuple[str, str, str, str]]:
    """Parse flags from help text into (flag, type, default, description) tuples."""
    rows: list[tuple[str, str, str, str]] = []
    pattern = re.compile(
        r"^\s+(--[\w-]+(?:\s+[\w/\[\]]+)?)\s{2,}(.*?)(?:\s+\[default:\s*(.*?)\])?\s*$"
    )
    for line in help_text.splitlines():
        m = pattern.match(line)
        if m:
            flag_part = m.group(1).strip()
            desc = m.group(2).strip()
            default = m.group(3) or ""
            parts = flag_part.split()
            flag = parts[0]
            flag_type = parts[1] if len(parts) > 1 else "flag"
            rows.append((flag, flag_type, default, desc))
    return rows


def format_command(name: str, help_text: str) -> str:
    lines = [f"## `agentsec {name}`\n"]
    in_desc = False
    for line in help_text.splitlines():
        if line.strip().startswith("Usage:"):
            in_desc = True
            continue
        if in_desc and line.strip() and not line.strip().startswith("-") and not line.strip().startswith("╭"):
            lines.append(line.strip() + "\n")
            in_desc = False
            break

    rows = parse_flags(help_text)
    if rows:
        lines.append("| Flag | Type | Default | Description |")
        lines.append("|------|------|---------|-------------|")
        for flag, ftype, default, desc in rows:
            default_str = f"`{default}`" if default else "—"
            lines.append(f"| `{flag}` | `{ftype}` | {default_str} | {desc} |")
        lines.append("")

    return "\n".join(lines)


SUBCOMMANDS = [
    ("scan", ["scan"]),
    ("probe", ["probe"]),
    ("probes list", ["probes", "list"]),
    ("report", ["report"]),
    ("serve", ["serve"]),
]


def main() -> None:
    content_lines = [
        "<!-- AUTO-GENERATED — do not edit directly. Re-run scripts/wiki/generate_cli_reference.py -->",
        "",
        "# CLI Commands",
        "",
        "Full flag reference for all agentsec commands.",
        "",
        "> For narrative usage examples, see [CLI Reference](../using/CLI-Reference).",
        "",
    ]

    for display_name, args in SUBCOMMANDS:
        help_text = run_help(args)
        content_lines.append(format_command(display_name, help_text))
        content_lines.append("---\n")

    out_path = Path(__file__).parent.parent.parent / "wiki" / "reference" / "CLI-Commands.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(content_lines) + "\n")
    print(f"Written {out_path}")


if __name__ == "__main__":
    main()
