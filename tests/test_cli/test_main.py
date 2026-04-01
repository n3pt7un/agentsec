"""Integration tests for CLI commands."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from agentsec.cli.main import app

runner = CliRunner()


class TestProbesList:
    """Tests for the 'agentsec probes list' command."""

    def test_lists_all_probes(self):
        result = runner.invoke(app, ["probes", "list"])
        assert result.exit_code == 0
        # All 6 probes should appear
        assert "ASI01-INDIRECT-INJECT" in result.output
        assert "ASI01-ROLE-CONFUSION" in result.output
        assert "ASI03-CRED-EXTRACTION" in result.output
        assert "ASI03-IMPERSONATION" in result.output
        assert "ASI06-MEMORY-POISON" in result.output
        assert "ASI06-CONTEXT-LEAK" in result.output

    def test_filter_by_category(self):
        result = runner.invoke(app, ["probes", "list", "--category", "ASI01"])
        assert result.exit_code == 0
        assert "ASI01-INDIRECT-INJECT" in result.output
        assert "ASI03" not in result.output

    def test_filter_nonexistent_category(self):
        result = runner.invoke(app, ["probes", "list", "--category", "ASI99"])
        assert result.exit_code == 0
        assert "No probes found" in result.output


class TestScanCommand:
    """Tests for the 'agentsec scan' command."""

    def test_scan_json_output(self):
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/simple_chain.py",
                "--format",
                "json",
                "--no-vulnerable",
            ],
        )
        assert result.exit_code == 0
        # Extract JSON from output (may contain Rich formatting before/after)
        # The JSON output should contain scan_result
        assert "scan_result" in result.output or "findings" in result.output

    def test_scan_markdown_output(self):
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/simple_chain.py",
                "--format",
                "markdown",
                "--no-vulnerable",
            ],
        )
        assert result.exit_code == 0
        assert "agentsec Scan Report" in result.output

    def test_scan_with_category_filter(self):
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/simple_chain.py",
                "--categories",
                "ASI01",
                "--format",
                "markdown",
                "--no-vulnerable",
            ],
        )
        assert result.exit_code == 0
        assert "ASI01" in result.output

    def test_scan_writes_to_file(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/simple_chain.py",
                "--format",
                "json",
                "--output",
                output_path,
                "--no-vulnerable",
            ],
        )
        assert result.exit_code == 0
        content = Path(output_path).read_text()
        parsed = json.loads(content)
        assert "scan_result" in parsed
        Path(output_path).unlink()

    def test_scan_invalid_target(self):
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "langgraph",
                "--target",
                "nonexistent.py",
            ],
        )
        assert result.exit_code == 1

    def test_scan_invalid_adapter(self):
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "unknown",
                "--target",
                "tests/fixtures/simple_chain.py",
            ],
        )
        assert result.exit_code != 0


class TestProbeCommand:
    """Tests for the 'agentsec probe' single-probe command."""

    def test_single_probe_run(self):
        result = runner.invoke(
            app,
            [
                "probe",
                "ASI01-INDIRECT-INJECT",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/supervisor_crew.py",
            ],
        )
        assert result.exit_code == 0
        assert "ASI01-INDIRECT-INJECT" in result.output

    def test_nonexistent_probe_id(self):
        result = runner.invoke(
            app,
            [
                "probe",
                "NONEXISTENT-PROBE",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/simple_chain.py",
            ],
        )
        assert result.exit_code == 1


class TestReportCommand:
    """Tests for the 'agentsec report' command."""

    def test_report_from_json_file(self):
        # First, generate a JSON file via scan
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            output_path = f.name

        runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/simple_chain.py",
                "--format",
                "json",
                "--output",
                output_path,
                "--no-vulnerable",
            ],
        )

        # Now generate markdown from it
        result = runner.invoke(
            app,
            [
                "report",
                "--input",
                output_path,
                "--format",
                "markdown",
            ],
        )
        assert result.exit_code == 0
        assert "agentsec Scan Report" in result.output
        Path(output_path).unlink()

    def test_report_nonexistent_file(self):
        result = runner.invoke(
            app,
            [
                "report",
                "--input",
                "nonexistent.json",
            ],
        )
        assert result.exit_code == 1

    def test_report_json_to_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            output_path = f.name

        runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/simple_chain.py",
                "--format",
                "json",
                "--output",
                output_path,
                "--no-vulnerable",
            ],
        )

        result = runner.invoke(
            app,
            [
                "report",
                "--input",
                output_path,
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        assert "scan_result" in result.output
        Path(output_path).unlink()
