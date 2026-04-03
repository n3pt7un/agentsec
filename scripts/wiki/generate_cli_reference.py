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
        env={**__import__("os").environ, "NO_COLOR": "1", "TERM": "dumb"},
    )
    if result.returncode != 0:
        print(
            f"WARNING: 'agentsec {' '.join(args)} --help' exited with code {result.returncode}",
            file=sys.stderr,
        )
    return result.stdout or result.stderr


def _strip_box(line: str) -> str:
    """Strip leading/trailing box-drawing border characters and whitespace from a help line."""
    # Lines look like: │    --flag    TEXT  description    │
    s = line.strip()
    if s.startswith("│"):
        s = s[1:]
    if s.endswith("│"):
        s = s[:-1]
    return s


def parse_flags(help_text: str) -> list[tuple[str, str, str, str]]:
    """Parse flags from Typer box-drawing help text into (flag, type, default, description) tuples.

    Handles multi-line descriptions and [default: ...] annotations that appear on
    their own continuation lines inside the box.
    """
    rows: list[tuple[str, str, str, str]] = []

    # Matches the start of a flag line inside the box.
    # Typer renders boolean toggles as two separate flags on the same line:
    #   --verbose           --no-verbose             Verbose output ...
    # We capture the first --flag and the optional --no-flag (group 2),
    # the optional TYPE token (group 3), and the description (group 4).
    flag_line_re = re.compile(
        r"^\s*\*?\s*(--[\w-]+)\s+(--no-[\w-]+)?\s*(TEXT|INTEGER|FLOAT|PATH|BOOLEAN)?\s*(.*?)\s*$"
    )
    default_re = re.compile(r"\[default:\s*(.*?)\]")
    default_open_re = re.compile(r"\[default:\s*(.*)")  # [default: split across lines
    required_re = re.compile(r"\[required\]")

    lines = help_text.splitlines()
    current: tuple[str, str, str, str] | None = None  # (flag, type, default, desc)
    pending_default: str | None = None  # accumulates split [default: value\n...]

    for raw_line in lines:
        inner = _strip_box(raw_line)

        # Skip box borders and section headers
        if not inner.strip() or inner.strip().startswith("╭") or inner.strip().startswith("╰") or inner.strip().startswith("─"):
            if current is not None:
                rows.append(current)
                current = None
            pending_default = None
            continue

        m = flag_line_re.match(inner)
        if m:
            # Save any pending row
            if current is not None:
                rows.append(current)
            pending_default = None

            flag = m.group(1)
            no_flag = m.group(2)  # e.g. "--no-verbose" for boolean toggles
            flag_type = m.group(3) or ("flag" if no_flag else "flag")
            desc_part = m.group(4).strip()

            # Check for complete [default: value] on this same line
            default = ""
            def_match = default_re.search(desc_part)
            if def_match:
                default = def_match.group(1).strip()
                desc_part = default_re.sub("", desc_part).strip()
            else:
                # Check for incomplete [default: split across lines
                open_match = default_open_re.search(desc_part)
                if open_match:
                    pending_default = open_match.group(1).strip()
                    desc_part = default_open_re.sub("", desc_part).strip()
            if required_re.search(desc_part):
                desc_part = required_re.sub("", desc_part).strip()

            current = (flag, flag_type, default, desc_part)
        elif current is not None:
            # Continuation line — append to description or extract default
            flag, flag_type, default, desc = current
            stripped = inner.strip()

            if pending_default is not None:
                # We're accumulating a split [default: ...]
                close_idx = stripped.find("]")
                if close_idx >= 0:
                    # Found the closing bracket
                    pending_default = (pending_default + " " + stripped[:close_idx]).strip()
                    if not default:
                        default = pending_default
                    remaining = stripped[close_idx + 1:].strip()
                    pending_default = None
                    if remaining:
                        desc = (desc + " " + remaining).strip() if desc else remaining
                else:
                    # Still accumulating
                    pending_default = (pending_default + " " + stripped).strip()
                current = (flag, flag_type, default, desc)
                continue

            def_match = default_re.search(stripped)
            if def_match:
                new_default = def_match.group(1).strip()
                if not default:
                    default = new_default
                # Remove the [default: ...] token from continuation
                stripped = default_re.sub("", stripped).strip()
            else:
                open_match = default_open_re.search(stripped)
                if open_match:
                    pending_default = open_match.group(1).strip()
                    stripped = default_open_re.sub("", stripped).strip()
            if required_re.search(stripped):
                stripped = required_re.sub("", stripped).strip()

            if stripped:
                desc = (desc + " " + stripped).strip() if desc else stripped
            current = (flag, flag_type, default, desc)

    if current is not None:
        rows.append(current)

    # Filter out --help entries
    rows = [(f, t, d, desc) for f, t, d, desc in rows if f != "--help"]
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
