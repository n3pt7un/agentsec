"""agentsec CLI entry point."""

import typer

app = typer.Typer(
    name="agentsec",
    help="Red-team and harden multi-agent LLM systems against OWASP Agentic Top 10.",
    no_args_is_help=True,
)

probes_app = typer.Typer(help="Manage and list available probes.")
app.add_typer(probes_app, name="probes")


@app.command()
def scan(
    adapter: str = typer.Option(..., help="Adapter to use (e.g. langgraph)"),
    target: str = typer.Option(..., help="Path to target agent system"),
    categories: list[str] = typer.Option([], help="OWASP categories to test (default: all)"),  # noqa: B008
    output: str | None = typer.Option(None, help="Write findings to this file"),
    format: str = typer.Option("markdown", help="Report format: markdown, html, json, sarif"),
    verbose: bool = typer.Option(False, help="Verbose output"),
) -> None:
    """Scan a multi-agent system for OWASP Agentic vulnerabilities."""
    typer.echo("Scan command — not yet implemented")


@app.command()
def probe(
    probe_id: str = typer.Argument(help="Probe ID to run (e.g. ASI01-INDIRECT-INJECT)"),
    adapter: str = typer.Option(..., help="Adapter to use (e.g. langgraph)"),
    target: str = typer.Option(..., help="Path to target agent system"),
) -> None:
    """Run a single probe for debugging."""
    typer.echo("Probe command — not yet implemented")


@probes_app.command("list")
def probes_list() -> None:
    """List available probes."""
    typer.echo("Probes list — not yet implemented")


@app.command()
def report(
    input: str = typer.Option(..., help="Path to findings JSON file"),
    format: str = typer.Option("markdown", help="Report format: markdown, html, json, sarif"),
    output: str | None = typer.Option(None, help="Write report to this file"),
) -> None:
    """Generate report from findings."""
    typer.echo("Report command — not yet implemented")
