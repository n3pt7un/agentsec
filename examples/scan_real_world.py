#!/usr/bin/env python3
"""Scan a real-world LangGraph pipeline and save the report.

Builds the email automation harness (classify → retrieve → draft →
quality_check → send) and runs all agentsec probes against it.
Report is written to reports/email_automation.md and also printed to stdout.

No API keys required — the harness uses a deterministic echo model.
No optional dependencies required — base LangGraph only (uv sync is enough).

Usage:
    uv run python examples/scan_real_world.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import anyio
from tests.targets.email_automation_harness import build_email_automation_target

from agentsec.adapters.langgraph import LangGraphAdapter
from agentsec.core.config import ScanConfig
from agentsec.core.scanner import Scanner
from agentsec.reporters.markdown import generate_markdown


async def main() -> None:
    """Run the scan and save the report."""
    graph = build_email_automation_target(vulnerable=True)
    adapter = LangGraphAdapter(graph)
    config = ScanConfig()

    scanner = Scanner(adapter, config)
    result = await scanner.run(target="email_automation_harness")

    report = generate_markdown(result)

    async def _save_report() -> None:
        out = Path("reports/email_automation.md")
        await anyio.to_thread.run_sync(lambda: out.parent.mkdir(parents=True, exist_ok=True))
        await anyio.to_thread.run_sync(lambda: out.write_text(report))
        print(report)
        print(f"\nReport saved to {out}")

    await _save_report()


if __name__ == "__main__":
    asyncio.run(main())
