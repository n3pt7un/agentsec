"""agentsec CLI entry point."""

from __future__ import annotations

import asyncio
import json
import logging
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console

from agentsec.core.config import DetectionMode, ScanConfig
from agentsec.core.loader import load_graph, make_adapter

app = typer.Typer(
    name="agentsec",
    help="Red-team and harden multi-agent LLM systems against OWASP Agentic Top 10.",
    no_args_is_help=True,
)

probes_app = typer.Typer(help="Manage and list available probes.")
app.add_typer(probes_app, name="probes")

console = Console()
logger = logging.getLogger(__name__)


def _write_output(content: str, output_path: str | None) -> None:
    """Write content to a file or stdout."""
    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        console.print(f"[green]Report written to {output_path}[/]")
    else:
        console.print(content)


# ── Commands ────────────────────────────────────────────────────────


@app.command()
def scan(
    adapter: str = typer.Option("langgraph", help="Adapter to use (e.g. langgraph)"),
    target: str = typer.Option(..., help="Path to target agent system"),
    categories: str | None = typer.Option(None, help="Comma-separated OWASP categories"),
    probes: str | None = typer.Option(None, help="Comma-separated probe IDs"),
    output: str | None = typer.Option(None, help="Write report to this file"),
    format: str = typer.Option("markdown", help="Report format: markdown, json"),
    verbose: bool = typer.Option(False, help="Verbose output — print each finding as it completes"),
    vulnerable: bool = typer.Option(True, help="Pass vulnerable flag to fixture builders"),
    smart: bool = typer.Option(False, help="Use LLM-powered smart payloads via OpenRouter"),
    model: str = typer.Option("anthropic/claude-sonnet-4.6", help="OpenRouter model identifier"),
    live: bool = typer.Option(False, help="Use a real LLM via OpenRouter for target agents"),
    target_model: str | None = typer.Option(
        None, help="OpenRouter model ID for target agents (live mode only)"
    ),
    detection_mode: str = typer.Option(
        "marker_then_llm",
        help="Detection strategy: 'marker_then_llm' (default) or 'llm_only'. "
        "'llm_only' requires --smart.",
    ),
) -> None:
    """Scan a multi-agent system for OWASP Agentic vulnerabilities."""
    cat_list = [c.strip() for c in categories.split(",")] if categories else None
    probe_list = [p.strip() for p in probes.split(",")] if probes else None

    try:
        mode = DetectionMode(detection_mode)
    except ValueError:
        console.print(
            f"[red]Error:[/] Invalid detection mode '{detection_mode}'. "
            "Choose 'marker_then_llm' or 'llm_only'."
        )
        raise typer.Exit(code=1) from None

    from pydantic import ValidationError as PydanticValidationError

    try:
        config = ScanConfig(
            categories=cat_list,
            probes=probe_list,
            verbose=verbose,
            smart=smart,
            llm_model=model,
            detection_mode=mode,
        )
    except PydanticValidationError as exc:
        for error in exc.errors():
            console.print(f"[red]Error:[/] {error['msg']}")
        raise typer.Exit(code=1) from exc

    try:
        graph = load_graph(target, vulnerable=vulnerable, live=live, target_model=target_model)
    except ValueError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    adapter_inst = make_adapter(adapter, graph)

    from agentsec.core.exceptions import LLMProviderError

    try:
        result = asyncio.run(_run_scan(adapter_inst, config, target, verbose))
    except LLMProviderError as exc:
        console.print(f"\n[bold red]LLM Provider Error:[/] {exc}")
        if "API key" in str(exc):
            console.print(
                "[yellow]Set AGENTSEC_OPENROUTER_API_KEY environment variable "
                "or check your key at https://openrouter.ai/keys[/]"
            )
        raise typer.Exit(code=1) from exc

    # Post-scan usage summary (smart mode only)
    if result.smart and result.models_used:
        from rich.table import Table as RichTable

        usage_table = RichTable(show_header=False, box=None, padding=(0, 1))
        usage_table.add_row(
            "[dim]Models[/]",
            ", ".join(result.models_used),
        )
        usage_table.add_row(
            "[dim]Tokens[/]",
            f"{result.total_input_tokens:,} in · {result.total_output_tokens:,} out",
        )
        cost_str = f"${result.total_cost_usd:.4f}" if result.total_cost_usd is not None else "—"
        usage_table.add_row("[dim]Cost[/]", cost_str)
        console.print(usage_table)

    # Generate report
    if format == "json":
        from agentsec.reporters.json_report import generate_json

        report = generate_json(result)
    else:
        from agentsec.reporters.markdown import generate_markdown

        report = generate_markdown(result)

    _write_output(report, output)


async def _run_scan(adapter, config: ScanConfig, target: str, verbose: bool):
    """Run the scan with a live Rich dashboard."""
    from agentsec.cli.display import ScanDisplay, print_finding_summary
    from agentsec.core.scanner import Scanner

    scanner = Scanner(adapter, config)

    # Discover agents first for the dashboard
    agents = await adapter.discover()

    # Determine probe count and category breakdown
    if len(scanner._registry) == 0:
        scanner._registry.discover_probes()
    all_probes = [cls() for cls in scanner._registry.probe_classes()]
    if config.probes:
        allowed = set(config.probes)
        all_probes = [p for p in all_probes if p.metadata().id in allowed]
    if config.categories:
        allowed_cats = set(config.categories)
        all_probes = [p for p in all_probes if p.metadata().category.value in allowed_cats]

    total = len(all_probes)
    cat_counts: dict[str, int] = Counter(p.metadata().category.value for p in all_probes)

    display = ScanDisplay(target, agents, total)
    display.set_category_totals(dict(cat_counts))

    def callback(probe_id: str, status: str, finding):
        display.progress_callback(probe_id, status, finding)
        if verbose and finding and status != "started":
            print_finding_summary(finding)

    with display:
        result = await scanner.run(target=target, progress_callback=callback)

    return result


@app.command()
def probe(
    probe_id: str = typer.Argument(help="Probe ID to run (e.g. ASI01-INDIRECT-INJECT)"),
    adapter: str = typer.Option("langgraph", help="Adapter to use (e.g. langgraph)"),
    target: str = typer.Option(..., help="Path to target agent system"),
    vulnerable: bool = typer.Option(True, help="Pass vulnerable flag to fixture builders"),
    smart: bool = typer.Option(False, help="Use LLM-powered smart payloads via OpenRouter"),
    model: str = typer.Option("anthropic/claude-sonnet-4.6", help="OpenRouter model identifier"),
    live: bool = typer.Option(False, help="Use a real LLM via OpenRouter for target agents"),
    target_model: str | None = typer.Option(
        None, help="OpenRouter model ID for target agents (live mode only)"
    ),
) -> None:
    """Run a single probe for debugging."""
    try:
        graph = load_graph(target, vulnerable=vulnerable, live=live, target_model=target_model)
    except ValueError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    adapter_inst = make_adapter(adapter, graph)

    config = ScanConfig(probes=[probe_id], verbose=True, smart=smart, llm_model=model)

    from agentsec.core.scanner import Scanner

    scanner = Scanner(adapter_inst, config)

    from agentsec.core.exceptions import LLMProviderError

    try:
        result = asyncio.run(scanner.run(target=target))
    except LLMProviderError as exc:
        console.print(f"\n[bold red]LLM Provider Error:[/] {exc}")
        if "API key" in str(exc):
            console.print(
                "[yellow]Set AGENTSEC_OPENROUTER_API_KEY environment variable "
                "or check your key at https://openrouter.ai/keys[/]"
            )
        raise typer.Exit(code=1) from exc

    if not result.findings:
        console.print(f"[yellow]No probe found with ID: {probe_id}[/]")
        raise typer.Exit(code=1)

    finding = result.findings[0]
    from agentsec.cli.display import print_finding_summary

    print_finding_summary(finding)

    # Print full details
    console.print(f"\n[bold]Probe:[/] {finding.probe_name}")
    console.print(f"[bold]Status:[/] {finding.status.value.upper()}")
    console.print(f"[bold]Severity:[/] {finding.severity.value.upper()}")
    console.print(f"[bold]Description:[/] {finding.description}")
    if finding.evidence:
        console.print("\n[bold]Evidence:[/]")
        console.print(f"  Attack: {finding.evidence.attack_input}")
        console.print(f"  Target: {finding.evidence.target_agent}")
        console.print(f"  Response: {finding.evidence.agent_response}")
    if finding.blast_radius:
        console.print(f"\n[bold]Blast radius:[/] {finding.blast_radius}")
    console.print(f"\n[bold]Remediation:[/] {finding.remediation.summary}")


@probes_app.command("list")
def probes_list(
    category: str | None = typer.Option(None, help="Filter by OWASP category (e.g. ASI01)"),
) -> None:
    """List available probes."""
    from agentsec.cli.display import print_probes_table
    from agentsec.probes.registry import ProbeRegistry

    registry = ProbeRegistry()
    registry.discover_probes()
    all_meta = registry.list_all()

    if category:
        all_meta = [m for m in all_meta if m.category.value == category.strip().upper()]

    if not all_meta:
        console.print("[yellow]No probes found.[/]")
        return

    print_probes_table(all_meta)


@app.command()
def report(
    input: str = typer.Option(..., help="Path to findings JSON file"),
    format: str = typer.Option("markdown", help="Report format: markdown, json"),
    output: str | None = typer.Option(None, help="Write report to this file"),
) -> None:
    """Generate report from a previously saved findings JSON file."""
    input_path = Path(input)
    if not input_path.exists():
        console.print(f"[red]Error:[/] File not found: {input}")
        raise typer.Exit(code=1)

    from agentsec.core.scanner import ScanResult

    raw = json.loads(input_path.read_text())

    # Handle both raw ScanResult and metadata-wrapped JSON
    if "scan_result" in raw:
        raw = raw["scan_result"]

    try:
        result = ScanResult.model_validate(raw)
    except Exception as exc:
        console.print(f"[red]Error parsing findings:[/] {exc}")
        raise typer.Exit(code=1) from exc

    if format == "json":
        from agentsec.reporters.json_report import generate_json

        content = generate_json(result)
    else:
        from agentsec.reporters.markdown import generate_markdown

        content = generate_markdown(result)

    _write_output(content, output)


@app.command()
def serve(
    port: int = typer.Option(8457, help="Port to serve the dashboard on"),
    host: str = typer.Option("127.0.0.1", help="Host to bind to"),
    reload: bool = typer.Option(False, help="Enable auto-reload for development"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open browser on start"),
) -> None:
    """Start the agentsec web dashboard."""
    try:
        import uvicorn
    except ImportError as exc:
        console.print(
            "[red]Error:[/] Dashboard requires extra dependencies.\n"
            "Install with: [bold]uv sync --extra dashboard[/]"
        )
        raise typer.Exit(code=1) from exc

    url = f"http://{host}:{port}"
    console.print(f"[cyan]Starting agentsec dashboard at {url}[/]")

    if open_browser:
        import threading
        import webbrowser

        threading.Timer(1.5, webbrowser.open, args=[url]).start()

    uvicorn.run(
        "agentsec.dashboard.app:app",
        host=host,
        port=port,
        reload=reload,
    )
