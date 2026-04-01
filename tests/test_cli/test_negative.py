"""Negative and edge-case tests for CLI commands."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from agentsec.cli.main import app

runner = CliRunner()


# ------------------------------------------------------------------
# scan: invalid inputs
# ------------------------------------------------------------------


class TestScanInvalidInputs:
    """Negative tests for the scan command."""

    def test_nonexistent_target_file(self):
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "langgraph",
                "--target",
                "/tmp/does_not_exist_at_all.py",
            ],
        )
        assert result.exit_code == 1

    def test_target_file_without_build_function(self):
        """A Python file that has no build_* function or graph attribute."""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("x = 42\n")
            f.flush()
            path = f.name

        try:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--adapter",
                    "langgraph",
                    "--target",
                    path,
                ],
            )
            assert result.exit_code == 1
        finally:
            Path(path).unlink()

    def test_invalid_adapter_value(self):
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "crewai",
                "--target",
                "tests/fixtures/simple_chain.py",
            ],
        )
        assert result.exit_code != 0

    def test_categories_matching_no_probes(self):
        """--categories with a category that has no probes should produce an empty scan."""
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/simple_chain.py",
                "--categories",
                "ASI10",
                "--format",
                "json",
                "--no-vulnerable",
            ],
        )
        assert result.exit_code == 0
        # Should still produce valid output with 0 findings
        assert "findings" in result.output or "scan_result" in result.output

    def test_probes_with_nonexistent_id(self):
        """--probes with a probe ID that doesn't exist should produce an empty scan."""
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/simple_chain.py",
                "--probes",
                "FAKE-PROBE-999",
                "--format",
                "json",
                "--no-vulnerable",
            ],
        )
        assert result.exit_code == 0
        # Should have 0 findings
        assert "scan_result" in result.output or "findings" in result.output


# ------------------------------------------------------------------
# scan: --output flag writes files
# ------------------------------------------------------------------


class TestScanOutputFlag:
    """Verify --output writes actual files for both formats."""

    def test_output_writes_json_file(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name

        try:
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
                    out,
                    "--no-vulnerable",
                ],
            )
            assert result.exit_code == 0
            content = Path(out).read_text()
            parsed = json.loads(content)
            assert "scan_result" in parsed
            assert "metadata" in parsed
        finally:
            Path(out).unlink(missing_ok=True)

    def test_output_writes_markdown_file(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            out = f.name

        try:
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
                    "--output",
                    out,
                    "--no-vulnerable",
                ],
            )
            assert result.exit_code == 0
            content = Path(out).read_text()
            assert "agentsec Scan Report" in content
        finally:
            Path(out).unlink(missing_ok=True)


# ------------------------------------------------------------------
# scan: --vulnerable false flag
# ------------------------------------------------------------------


class TestVulnerableFalseFlag:
    """Verify --no-vulnerable produces all RESISTANT results."""

    def test_all_resistant_with_no_vulnerable_flag(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name

        try:
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
                    "--categories",
                    "ASI01",
                    "--output",
                    out,
                ],
            )
            assert result.exit_code == 0
            parsed = json.loads(Path(out).read_text())
            findings = parsed["scan_result"]["findings"]
            assert len(findings) > 0
            for finding in findings:
                assert finding["status"] in ("resistant", "skipped"), (
                    f"Expected RESISTANT or SKIPPED, got {finding['status']} "
                    f"for {finding['probe_id']}"
                )
        finally:
            Path(out).unlink(missing_ok=True)


# ------------------------------------------------------------------
# probe: invalid inputs
# ------------------------------------------------------------------


class TestProbeInvalidInputs:
    """Negative tests for the single probe command."""

    def test_invalid_probe_id(self):
        result = runner.invoke(
            app,
            [
                "probe",
                "NONEXISTENT-PROBE-XYZ",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/simple_chain.py",
            ],
        )
        assert result.exit_code == 1

    def test_invalid_target_for_probe(self):
        result = runner.invoke(
            app,
            [
                "probe",
                "ASI01-INDIRECT-INJECT",
                "--adapter",
                "langgraph",
                "--target",
                "/tmp/nope_not_here.py",
            ],
        )
        assert result.exit_code == 1


# ------------------------------------------------------------------
# report: invalid inputs
# ------------------------------------------------------------------


class TestReportInvalidInputs:
    """Negative tests for the report command."""

    def test_nonexistent_input_file(self):
        result = runner.invoke(
            app,
            [
                "report",
                "--input",
                "/tmp/nonexistent_findings.json",
            ],
        )
        assert result.exit_code == 1

    def test_report_output_writes_file(self):
        """Verify --output flag actually writes the report to a file."""
        # First create a JSON scan result
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            scan_path = f.name

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
                scan_path,
                "--no-vulnerable",
            ],
        )

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            report_path = f.name

        try:
            result = runner.invoke(
                app,
                [
                    "report",
                    "--input",
                    scan_path,
                    "--format",
                    "markdown",
                    "--output",
                    report_path,
                ],
            )
            assert result.exit_code == 0
            content = Path(report_path).read_text()
            assert "agentsec Scan Report" in content
        finally:
            Path(scan_path).unlink(missing_ok=True)
            Path(report_path).unlink(missing_ok=True)


# ------------------------------------------------------------------
# Empty scan result report generation
# ------------------------------------------------------------------


class TestEmptyScanReport:
    """Test report generation when scan has no findings."""

    def test_empty_findings_markdown(self):
        """Scan with --probes that match nothing should still produce valid markdown."""
        result = runner.invoke(
            app,
            [
                "scan",
                "--adapter",
                "langgraph",
                "--target",
                "tests/fixtures/simple_chain.py",
                "--probes",
                "NONEXISTENT-PROBE",
                "--format",
                "markdown",
                "--no-vulnerable",
            ],
        )
        assert result.exit_code == 0
        assert "agentsec Scan Report" in result.output

    def test_empty_findings_json(self):
        """Scan with --probes that match nothing should still produce valid JSON."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name

        try:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--adapter",
                    "langgraph",
                    "--target",
                    "tests/fixtures/simple_chain.py",
                    "--probes",
                    "NONEXISTENT-PROBE",
                    "--format",
                    "json",
                    "--output",
                    out,
                    "--no-vulnerable",
                ],
            )
            assert result.exit_code == 0
            parsed = json.loads(Path(out).read_text())
            assert parsed["scan_result"]["findings"] == []
            assert parsed["scan_result"]["total_probes"] == 0
        finally:
            Path(out).unlink(missing_ok=True)
