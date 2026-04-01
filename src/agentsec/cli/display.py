"""Rich live dashboard for agentsec scan progress."""

from __future__ import annotations

import time

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from agentsec.adapters.base import AgentInfo
from agentsec.core.finding import Finding, FindingStatus, Severity

console = Console()

# Severity emojis matching the markdown reporter.
_SEV_EMOJI: dict[str, str] = {
    "critical": "\U0001f534",
    "high": "\U0001f7e0",
    "medium": "\U0001f7e1",
    "low": "\U0001f535",
    "info": "\u2139\ufe0f",
}


class ScanDisplay:
    """Rich live dashboard shown during a scan.

    Provides a ``progress_callback`` compatible with ``Scanner.run()`` and
    a context-manager interface that wraps ``rich.live.Live``.
    """

    def __init__(self, target: str, agents: list[AgentInfo], total_probes: int) -> None:
        self._target = target
        self._agents = agents
        self._total = total_probes
        self._completed = 0
        self._findings: list[Finding] = []
        self._start = time.monotonic()

        # Per-category progress tracking
        self._category_total: dict[str, int] = {}
        self._category_done: dict[str, int] = {}
        self._category_vuln: dict[str, int] = {}

        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
        )
        self._overall_task = self._progress.add_task("Probes", total=total_probes)
        self._live: Live | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> ScanDisplay:
        self._live = Live(self._build_layout(), console=console, refresh_per_second=4)
        self._live.__enter__()
        return self

    def __exit__(self, *args) -> None:
        if self._live:
            self._live.__exit__(*args)

    # ------------------------------------------------------------------
    # Callback for Scanner
    # ------------------------------------------------------------------

    def progress_callback(self, probe_id: str, status: str, finding: Finding | None) -> None:
        """Called by Scanner.run() after each probe starts/completes."""
        if status == "started":
            return

        self._completed += 1
        self._progress.update(self._overall_task, completed=self._completed)

        if finding:
            self._findings.append(finding)
            cat = finding.category.value
            self._category_done[cat] = self._category_done.get(cat, 0) + 1
            if finding.status in (FindingStatus.VULNERABLE, FindingStatus.PARTIAL):
                self._category_vuln[cat] = self._category_vuln.get(cat, 0) + 1

        if self._live:
            self._live.update(self._build_layout())

    def set_category_totals(self, totals: dict[str, int]) -> None:
        """Set how many probes belong to each category (for progress bars)."""
        self._category_total = dict(totals)

    # ------------------------------------------------------------------
    # Layout building
    # ------------------------------------------------------------------

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._header_panel(), size=3),
            Layout(name="body"),
            Layout(self._stats_panel(), size=3),
        )
        layout["body"].split_row(
            Layout(self._agents_panel(), ratio=1),
            Layout(self._progress_panel(), ratio=2),
        )
        return layout

    def _header_panel(self) -> Panel:
        return Panel(
            f"[bold cyan]agentsec v0.1.0[/] — Scanning: [bold]{self._target}[/]",
            style="blue",
        )

    def _agents_panel(self) -> Panel:
        table = Table(title="Agents", show_lines=False, expand=True)
        table.add_column("Name", style="bold")
        table.add_column("Role")
        table.add_column("Tools")
        table.add_column("Downstream")
        for agent in self._agents:
            tools = ", ".join(agent.tools) if agent.tools else "—"
            downstream = ", ".join(agent.downstream_agents) if agent.downstream_agents else "—"
            table.add_row(agent.name, agent.role or "—", tools, downstream)
        return Panel(table)

    def _progress_panel(self) -> Panel:
        table = Table(title="Probe Progress", expand=True)
        table.add_column("Category")
        table.add_column("Progress")
        table.add_column("Findings")

        for cat in sorted(self._category_total):
            total = self._category_total[cat]
            done = self._category_done.get(cat, 0)
            vulns = self._category_vuln.get(cat, 0)
            bar = _bar_string(done, total)
            vuln_str = f"[red]{vulns}[/]" if vulns else "0"
            table.add_row(cat, f"{bar} {done}/{total}", vuln_str)

        # Overall progress bar at the bottom
        table.add_row(
            "[bold]Total[/]",
            f"{_bar_string(self._completed, self._total)} {self._completed}/{self._total}",
            "",
        )
        return Panel(table)

    def _stats_panel(self) -> Panel:
        elapsed = time.monotonic() - self._start
        vuln_count = sum(
            1
            for f in self._findings
            if f.status in (FindingStatus.VULNERABLE, FindingStatus.PARTIAL)
        )
        crit_count = sum(
            1
            for f in self._findings
            if f.status == FindingStatus.VULNERABLE and f.severity == Severity.CRITICAL
        )
        return Panel(
            f"Probes: {self._completed}/{self._total}  |  "
            f"Findings: [yellow]{vuln_count}[/]  |  "
            f"Critical: [red]{crit_count}[/]  |  "
            f"Elapsed: {elapsed:.1f}s",
            style="green",
        )


def print_finding_summary(finding: Finding) -> None:
    """Print a one-line finding summary for --verbose mode."""
    emoji = _SEV_EMOJI.get(finding.severity.value, "")
    status_color = {
        FindingStatus.VULNERABLE: "red",
        FindingStatus.PARTIAL: "yellow",
        FindingStatus.RESISTANT: "green",
        FindingStatus.ERROR: "red",
        FindingStatus.SKIPPED: "dim",
    }.get(finding.status, "white")
    console.print(
        f"  {emoji} {finding.probe_id}: [{status_color}]{finding.status.value.upper()}[/]"
    )


def print_probes_table(probes_metadata: list) -> None:
    """Print a Rich table of all registered probes."""
    table = Table(title="Available Probes")
    table.add_column("ID", style="bold cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Severity")
    table.add_column("Description")

    for meta in probes_metadata:
        sev_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }.get(meta.default_severity.value, "")
        table.add_row(
            meta.id,
            meta.category.value,
            f"[{sev_style}]{meta.default_severity.value.upper()}[/]",
            meta.description,
        )

    console.print(table)


# ── Helpers ─────────────────────────────────────────────────────────


def _bar_string(done: int, total: int, width: int = 15) -> str:
    """Render a simple text progress bar."""
    if total == 0:
        return "[dim]" + "░" * width + "[/]"
    filled = int(width * done / total)
    return "[green]" + "█" * filled + "[/]" + "░" * (width - filled)
