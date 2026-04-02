"""agentsec CLI entry point."""

from __future__ import annotations

import asyncio
import importlib.util
import inspect
import json
import logging
import sys
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console

from agentsec.core.config import ScanConfig

app = typer.Typer(
    name="agentsec",
    help="Red-team and harden multi-agent LLM systems against OWASP Agentic Top 10.",
    no_args_is_help=True,
)

probes_app = typer.Typer(help="Manage and list available probes.")
app.add_typer(probes_app, name="probes")

console = Console()
logger = logging.getLogger(__name__)


# ── Helpers ─────────────────────────────────────────────────────────


def _find_project_root(path: Path) -> Path | None:
    """Walk up from *path* looking for a pyproject.toml or .git directory."""
    for parent in [path, *path.parents]:
        if (parent / "pyproject.toml").exists() or (parent / ".git").exists():
            return parent
    return None


def _load_graph(
    target: str,
    *,
    vulnerable: bool = True,
    live: bool = False,
    target_model: str | None = None,
):
    """Dynamically import a target module and return its compiled graph.

    Looks for any callable starting with ``build_`` and invokes it, or
    falls back to a ``graph`` module attribute.

    Raises:
        typer.BadParameter: When no graph can be found.
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        raise typer.BadParameter(f"Target file not found: {target}")

    spec = importlib.util.spec_from_file_location("_target", str(target_path))
    if spec is None or spec.loader is None:
        raise typer.BadParameter(f"Cannot load module from: {target}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["_target"] = module

    # Add the target's parent directories to sys.path so relative imports
    # (e.g. ``from tests.fixtures.utils import ...``) resolve correctly.
    project_root = _find_project_root(target_path)
    if project_root and str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    spec.loader.exec_module(module)

    # Look for build_* callables
    for attr_name in sorted(dir(module)):
        if attr_name.startswith("build_") and callable(getattr(module, attr_name)):
            builder = getattr(module, attr_name)
            sig = inspect.signature(builder)
            kwargs: dict = {}
            if "live" in sig.parameters:
                kwargs["live"] = live
            if "target_model" in sig.parameters:
                kwargs["target_model"] = target_model
            if "vulnerable" in sig.parameters:
                kwargs["vulnerable"] = vulnerable
            return builder(**kwargs)

    # Fallback: look for a 'graph' attribute
    graph = getattr(module, "graph", None)
    if graph is not None:
        return graph

    raise typer.BadParameter(f"No build_* function or 'graph' attribute found in {target}")


def _make_adapter(adapter_name: str, graph):
    """Create an adapter instance from its name."""
    if adapter_name != "langgraph":
        raise typer.BadParameter(f"Unknown adapter: {adapter_name}. Supported: langgraph")

    from agentsec.adapters.langgraph import LangGraphAdapter

    return LangGraphAdapter(graph)


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
) -> None:
    """Scan a multi-agent system for OWASP Agentic vulnerabilities."""
    cat_list = [c.strip() for c in categories.split(",")] if categories else None
    probe_list = [p.strip() for p in probes.split(",")] if probes else None

    config = ScanConfig(
        categories=cat_list,
        probes=probe_list,
        verbose=verbose,
        smart=smart,
        llm_model=model,
    )

    try:
        graph = _load_graph(target, vulnerable=vulnerable, live=live, target_model=target_model)
    except (typer.BadParameter, ValueError) as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    adapter_inst = _make_adapter(adapter, graph)

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
        graph = _load_graph(target, vulnerable=vulnerable, live=live, target_model=target_model)
    except (typer.BadParameter, ValueError) as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    adapter_inst = _make_adapter(adapter, graph)

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
