# Session 10: SARIF Reporter + README Rewrite + v1.0.0b1 Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship SARIF output for CI/CD integration, rewrite the README to document all Phase 2 capabilities, and release as `agentsec-framework` v1.0.0b1 on PyPI.

**Architecture:** Three independent passes executed sequentially with a verification checkpoint after each. Pass 1 adds a new `reporters/sarif.py` module and wires it into CLI and dashboard. Pass 2 fully rewrites `README.md`. Pass 3 renames the package, bumps the version, and adds a manual publish workflow.

**Tech Stack:** Python 3.12, pydantic v2, fastapi (dashboard), typer (CLI), uv (build/publish), GitHub Actions

---

## File Map

### Pass 1 — SARIF Reporter
- **Create:** `src/agentsec/reporters/sarif.py` — `generate_sarif(result: ScanResult) -> str`
- **Create:** `tests/test_reporters/test_sarif.py` — unit tests for the SARIF reporter
- **Modify:** `src/agentsec/cli/main.py` — add `sarif` to `--format` in `scan` and `report` commands
- **Modify:** `src/agentsec/dashboard/routes/scans.py` — add `sarif` to single + batch export
- **Create:** `examples/ci_integration.yml` — GitHub Actions YAML for SARIF upload

### Pass 2 — README
- **Modify:** `README.md` — full rewrite

### Pass 3 — Packaging
- **Modify:** `pyproject.toml` — rename, version bump, classifiers, keywords
- **Modify:** `src/agentsec/__init__.py` — `__version__ = "1.0.0b1"`
- **Create:** `.github/workflows/publish.yml` — manual PyPI publish workflow

---

## Pass 1: SARIF Reporter

---

### Task 1: Write SARIF reporter tests

**Files:**
- Create: `tests/test_reporters/test_sarif.py`

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for the SARIF 2.1.0 report generator."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from agentsec.core.finding import (
    Evidence,
    Finding,
    FindingStatus,
    OWASPCategory,
    Remediation,
    Severity,
)
from agentsec.core.scanner import ScanResult
from agentsec.reporters.sarif import generate_sarif


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    now = datetime.now(UTC)
    findings = findings or []
    return ScanResult(
        target="tests/fixtures/simple_chain.py",
        findings=findings,
        agents_discovered=[],
        started_at=now,
        finished_at=now + timedelta(seconds=2),
        total_probes=len(findings),
        vulnerable_count=sum(1 for f in findings if f.status == FindingStatus.VULNERABLE),
        resistant_count=sum(1 for f in findings if f.status == FindingStatus.RESISTANT),
        error_count=0,
    )


def _vuln_finding(
    probe_id: str = "ASI01-INDIRECT-INJECT",
    severity: Severity = Severity.CRITICAL,
    category: OWASPCategory = OWASPCategory.ASI01,
) -> Finding:
    return Finding(
        probe_id=probe_id,
        probe_name="Indirect Prompt Injection via Crafted User Input",
        category=category,
        status=FindingStatus.VULNERABLE,
        severity=severity,
        description="Agent followed injected instruction.",
        evidence=Evidence(
            attack_input="Ignore previous instructions",
            target_agent="agent_a",
            agent_response="AGENTSEC_INJECT_abc",
        ),
        remediation=Remediation(summary="Use input boundary enforcer."),
    )


def _resistant_finding() -> Finding:
    return Finding(
        probe_id="ASI01-ROLE-CONFUSION",
        probe_name="Role Confusion via Identity Override",
        category=OWASPCategory.ASI01,
        status=FindingStatus.RESISTANT,
        severity=Severity.HIGH,
        description="Agent maintained its role.",
        remediation=Remediation(summary="No action needed."),
    )


class TestSarifStructure:
    def _parsed(self, findings):
        return json.loads(generate_sarif(_make_result(findings)))

    def test_top_level_schema_key(self):
        sarif = self._parsed([])
        assert "$schema" in sarif
        assert "2.1.0" in sarif["$schema"]

    def test_version_is_2_1_0(self):
        sarif = self._parsed([])
        assert sarif["version"] == "2.1.0"

    def test_runs_is_list_of_one(self):
        sarif = self._parsed([])
        assert isinstance(sarif["runs"], list)
        assert len(sarif["runs"]) == 1

    def test_driver_name(self):
        sarif = self._parsed([])
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "agentsec"

    def test_driver_version_present(self):
        sarif = self._parsed([])
        assert "version" in sarif["runs"][0]["tool"]["driver"]

    def test_driver_information_uri(self):
        sarif = self._parsed([])
        uri = sarif["runs"][0]["tool"]["driver"]["informationUri"]
        assert uri.startswith("https://")


class TestSarifRules:
    def _parsed(self, findings):
        return json.loads(generate_sarif(_make_result(findings)))

    def test_rules_include_all_probes_that_ran(self):
        # Both VULNERABLE and RESISTANT probes appear in rules
        findings = [_vuln_finding(), _resistant_finding()]
        rules = self._parsed(findings)["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "ASI01-INDIRECT-INJECT" in rule_ids
        assert "ASI01-ROLE-CONFUSION" in rule_ids

    def test_rule_has_short_description(self):
        findings = [_vuln_finding()]
        rules = self._parsed(findings)["runs"][0]["tool"]["driver"]["rules"]
        assert rules[0]["shortDescription"]["text"] != ""

    def test_rule_has_help_uri(self):
        findings = [_vuln_finding()]
        rules = self._parsed(findings)["runs"][0]["tool"]["driver"]["rules"]
        assert "helpUri" in rules[0]

    def test_rule_name_is_valid_identifier(self):
        """Rule name must contain no hyphens (SARIF spec)."""
        findings = [_vuln_finding()]
        rules = self._parsed(findings)["runs"][0]["tool"]["driver"]["rules"]
        assert "-" not in rules[0]["name"]


class TestSarifResults:
    def _parsed(self, findings):
        return json.loads(generate_sarif(_make_result(findings)))

    def test_no_results_for_empty_scan(self):
        sarif = self._parsed([])
        assert sarif["runs"][0]["results"] == []

    def test_resistant_finding_excluded_from_results(self):
        findings = [_resistant_finding()]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results == []

    def test_vulnerable_finding_produces_one_result(self):
        findings = [_vuln_finding(), _resistant_finding()]
        results = self._parsed(findings)["runs"][0]["results"]
        assert len(results) == 1

    def test_result_rule_id_matches_probe_id(self):
        findings = [_vuln_finding("ASI01-INDIRECT-INJECT")]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results[0]["ruleId"] == "ASI01-INDIRECT-INJECT"

    def test_critical_severity_maps_to_error(self):
        findings = [_vuln_finding(severity=Severity.CRITICAL)]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results[0]["level"] == "error"

    def test_high_severity_maps_to_error(self):
        findings = [_vuln_finding(severity=Severity.HIGH)]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results[0]["level"] == "error"

    def test_medium_severity_maps_to_warning(self):
        findings = [_vuln_finding(severity=Severity.MEDIUM)]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results[0]["level"] == "warning"

    def test_low_severity_maps_to_note(self):
        findings = [_vuln_finding(severity=Severity.LOW)]
        results = self._parsed(findings)["runs"][0]["results"]
        assert results[0]["level"] == "note"

    def test_result_message_contains_description(self):
        findings = [_vuln_finding()]
        results = self._parsed(findings)["runs"][0]["results"]
        assert "Agent followed injected instruction" in results[0]["message"]["text"]

    def test_result_location_uses_agent_uri(self):
        findings = [_vuln_finding()]
        results = self._parsed(findings)["runs"][0]["results"]
        loc = results[0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("agent://")
        assert "agent_a" in uri

    def test_result_logical_location_has_probe_id(self):
        findings = [_vuln_finding("ASI01-INDIRECT-INJECT")]
        results = self._parsed(findings)["runs"][0]["results"]
        logical = results[0]["locations"][0]["logicalLocations"][0]["name"]
        assert logical == "ASI01-INDIRECT-INJECT"

    def test_finding_without_evidence_uses_unknown_uri(self):
        finding = Finding(
            probe_id="ASI01-INDIRECT-INJECT",
            probe_name="Test",
            category=OWASPCategory.ASI01,
            status=FindingStatus.VULNERABLE,
            severity=Severity.HIGH,
            description="desc",
            remediation=Remediation(summary="fix"),
        )
        results = json.loads(generate_sarif(_make_result([finding])))["runs"][0]["results"]
        uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "agent://unknown"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/test_reporters/test_sarif.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError` or `ImportError` — `sarif` module doesn't exist yet.

---

### Task 2: Implement the SARIF reporter

**Files:**
- Create: `src/agentsec/reporters/sarif.py`

- [ ] **Step 1: Create the reporter**

```python
"""SARIF 2.1.0 report generator for agentsec scan results."""

from __future__ import annotations

import json
import re

from agentsec import __version__
from agentsec.core.finding import FindingStatus, Severity
from agentsec.core.scanner import ScanResult

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/n3pt7un/agentsec"

_SEVERITY_TO_LEVEL: dict[str, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _probe_id_to_name(probe_id: str) -> str:
    """Convert a probe ID like 'ASI01-INDIRECT-INJECT' to 'Asi01IndirectInject'."""
    parts = re.split(r"[-_]", probe_id)
    return "".join(p.capitalize() for p in parts)


def generate_sarif(result: ScanResult) -> str:
    """Generate SARIF 2.1.0 JSON from a ScanResult.

    Rules cover all probes that ran (all statuses). Results cover only
    VULNERABLE and PARTIAL findings — RESISTANT findings are excluded.

    Args:
        result: The scan result to render.

    Returns:
        A SARIF 2.1.0 JSON string.
    """
    # Deduplicate rules by probe_id, preserving insertion order
    seen_ids: set[str] = set()
    rules: list[dict] = []
    for finding in result.findings:
        if finding.probe_id not in seen_ids:
            seen_ids.add(finding.probe_id)
            rules.append(
                {
                    "id": finding.probe_id,
                    "name": _probe_id_to_name(finding.probe_id),
                    "shortDescription": {"text": finding.probe_name},
                    "helpUri": _INFORMATION_URI,
                    "properties": {"tags": [finding.category.value]},
                }
            )

    # Only emit results for actionable findings
    sarif_results: list[dict] = []
    for finding in result.findings:
        if finding.status not in (FindingStatus.VULNERABLE, FindingStatus.PARTIAL):
            continue

        target_agent = (
            finding.evidence.target_agent
            if finding.evidence and finding.evidence.target_agent
            else "unknown"
        )
        message_text = finding.description
        if finding.remediation and finding.remediation.summary:
            message_text += f"\n\nRemediation: {finding.remediation.summary}"

        sarif_results.append(
            {
                "ruleId": finding.probe_id,
                "level": _SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"agent://{target_agent}"}
                        },
                        "logicalLocations": [{"name": finding.probe_id}],
                    }
                ],
            }
        )

    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentsec",
                        "version": __version__,
                        "informationUri": _INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
uv run pytest tests/test_reporters/test_sarif.py -v
```

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/agentsec/reporters/sarif.py tests/test_reporters/test_sarif.py
git commit -m "FEAT: add SARIF 2.1.0 reporter"
```

---

### Task 3: Wire SARIF into CLI

**Files:**
- Modify: `src/agentsec/cli/main.py`

The `scan` command at line 52 and `report` command at line 272 both have `format: str = typer.Option(...)` and a conditional block that dispatches to `generate_markdown` or `generate_json`. Add `sarif` as a third option in both.

- [ ] **Step 1: Update `scan` command format dispatch (lines 133–142)**

Replace:
```python
    # Generate report
    if format == "json":
        from agentsec.reporters.json_report import generate_json

        report = generate_json(result)
    else:
        from agentsec.reporters.markdown import generate_markdown

        report = generate_markdown(result)
```

With:
```python
    # Generate report
    if format == "json":
        from agentsec.reporters.json_report import generate_json

        report = generate_json(result)
    elif format == "sarif":
        from agentsec.reporters.sarif import generate_sarif

        report = generate_sarif(result)
    else:
        from agentsec.reporters.markdown import generate_markdown

        report = generate_markdown(result)
```

- [ ] **Step 2: Update `scan` command `--format` help text (line 52)**

Replace:
```python
    format: str = typer.Option("markdown", help="Report format: markdown, json"),
```
With:
```python
    format: str = typer.Option("markdown", help="Report format: markdown, json, sarif"),
```

- [ ] **Step 3: Update `report` command format dispatch (lines 296–303)**

Replace:
```python
    if format == "json":
        from agentsec.reporters.json_report import generate_json

        content = generate_json(result)
    else:
        from agentsec.reporters.markdown import generate_markdown

        content = generate_markdown(result)
```

With:
```python
    if format == "json":
        from agentsec.reporters.json_report import generate_json

        content = generate_json(result)
    elif format == "sarif":
        from agentsec.reporters.sarif import generate_sarif

        content = generate_sarif(result)
    else:
        from agentsec.reporters.markdown import generate_markdown

        content = generate_markdown(result)
```

- [ ] **Step 4: Update `report` command `--format` help text (line 273)**

Replace:
```python
    format: str = typer.Option("markdown", help="Report format: markdown, json"),
```
With:
```python
    format: str = typer.Option("markdown", help="Report format: markdown, json, sarif"),
```

- [ ] **Step 5: Verify lint passes**

```bash
uv run ruff check src/agentsec/cli/main.py
```

Expected: No output (clean).

- [ ] **Step 6: Run full test suite**

```bash
uv run pytest -x -q
```

Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/agentsec/cli/main.py
git commit -m "ENH: add --format sarif to scan and report CLI commands"
```

---

### Task 4: Wire SARIF into dashboard export endpoints

**Files:**
- Modify: `src/agentsec/dashboard/routes/scans.py`

- [ ] **Step 1: Add import for generate_sarif at top of file (after line 15)**

Replace:
```python
from agentsec.reporters.json_report import generate_json
from agentsec.reporters.markdown import generate_markdown
```
With:
```python
from agentsec.reporters.json_report import generate_json
from agentsec.reporters.markdown import generate_markdown
from agentsec.reporters.sarif import generate_sarif
```

- [ ] **Step 2: Extend ExportRequest.format type (line 54)**

Replace:
```python
    format: Literal["md", "json"]
```
With:
```python
    format: Literal["md", "json", "sarif"]
```

- [ ] **Step 3: Add sarif branch in `batch_export_scans` (lines 92–97)**

Replace:
```python
    if request.format == "md":
        generate = generate_markdown
        ext = "md"
    else:
        generate = generate_json
        ext = "json"
```
With:
```python
    if request.format == "md":
        generate = generate_markdown
        ext = "md"
    elif request.format == "sarif":
        generate = generate_sarif
        ext = "sarif"
    else:
        generate = generate_json
        ext = "json"
```

- [ ] **Step 4: Update single-scan export validation and dispatch (lines 128–143)**

Replace:
```python
    if format not in ("md", "json"):
        raise HTTPException(status_code=400, detail="format must be 'md' or 'json'")

    job = _scan_manager.get_job(scan_id)
    result = job.result if job and job.result else _store.load(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    if format == "md":
        content = generate_markdown(result)
        media_type = "text/markdown"
        filename = f"scan-{scan_id}.md"
    else:
        content = generate_json(result)
        media_type = "application/json"
        filename = f"scan-{scan_id}.json"
```
With:
```python
    if format not in ("md", "json", "sarif"):
        raise HTTPException(status_code=400, detail="format must be 'md', 'json', or 'sarif'")

    job = _scan_manager.get_job(scan_id)
    result = job.result if job and job.result else _store.load(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    if format == "md":
        content = generate_markdown(result)
        media_type = "text/markdown"
        filename = f"scan-{scan_id}.md"
    elif format == "sarif":
        content = generate_sarif(result)
        media_type = "application/sarif+json"
        filename = f"scan-{scan_id}.sarif"
    else:
        content = generate_json(result)
        media_type = "application/json"
        filename = f"scan-{scan_id}.json"
```

- [ ] **Step 5: Verify lint and tests pass**

```bash
uv run ruff check src/agentsec/dashboard/routes/scans.py
uv run pytest -x -q
```

Expected: Clean lint, all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/agentsec/dashboard/routes/scans.py
git commit -m "ENH: add SARIF export to dashboard single and batch export endpoints"
```

---

### Task 5: Add CI integration example

**Files:**
- Create: `examples/ci_integration.yml`

- [ ] **Step 1: Create the file**

```yaml
# Example: Run agentsec in CI and upload SARIF findings to GitHub Security tab
#
# Prerequisites:
#   1. pip install agentsec-framework (or add to your requirements)
#   2. Your agent target file must be importable from the repo root
#
# The GitHub Security tab will display agentsec findings alongside
# CodeQL and other SAST results after the upload-sarif step.

name: Agent Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  agentsec:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # required for upload-sarif

    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v4

      - name: Install agentsec
        run: uv pip install agentsec-framework

      - name: Run security scan
        run: |
          agentsec scan \
            --adapter langgraph \
            --target ./src/agent.py \
            --format sarif \
            --output results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

- [ ] **Step 2: Run full test suite and lint**

```bash
uv run pytest -x -q && uv run ruff check src/ tests/
```

Expected: All tests pass, clean lint.

- [ ] **Step 3: Commit**

```bash
git add examples/ci_integration.yml
git commit -m "DOCS: add GitHub Actions CI integration example for SARIF upload"
```

---

## Pass 2: README Rewrite

---

### Task 6: Rewrite README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace README.md entirely**

Write the following content to `README.md`:

```markdown
# agentsec

> Red-team and harden multi-agent LLM systems against OWASP Agentic Top 10

[![PyPI](https://img.shields.io/pypi/v/agentsec-framework)](https://pypi.org/project/agentsec-framework/)
[![Tests](https://img.shields.io/github/actions/workflow/status/n3pt7un/agentsec/ci.yml?label=tests)](https://github.com/n3pt7un/agentsec/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

agentsec probes your multi-agent LLM system for vulnerabilities, scores findings against the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), and generates actionable remediation reports with copy-pasteable fixes.

**Break your agents. Fix the holes. Ship with confidence.**

---

## Quick Start

```bash
pip install agentsec-framework
```

```bash
agentsec scan --adapter langgraph --target ./my_graph.py
```

agentsec discovers your agents, runs 20 attack probes across all 10 OWASP Agentic categories, and prints a rich report with findings and remediations.

<!-- SCREENSHOT: terminal-scan.png — terminal showing the Rich live dashboard during a scan, with probe progress bars and a summary table of findings -->

---

## What It Tests

20 probes across 10 OWASP Agentic categories:

| Probe ID | Category | Severity | What It Tests |
|----------|----------|----------|---------------|
| `ASI01-INDIRECT-INJECT` | ASI01 Agent Goal Hijacking | CRITICAL | Indirect prompt injection via crafted user input |
| `ASI01-ROLE-CONFUSION` | ASI01 Agent Goal Hijacking | HIGH | Role confusion via identity override |
| `ASI02-PARAM-INJECTION` | ASI02 Tool Misuse & Exploitation | HIGH | Tool parameter injection (SQLi, shell, path traversal) |
| `ASI02-TOOL-CHAIN-ABUSE` | ASI02 Tool Misuse & Exploitation | HIGH | Tool chain abuse for unauthorized data exfiltration |
| `ASI03-CRED-EXTRACTION` | ASI03 Identity & Privilege Abuse | CRITICAL | Credential extraction via context interrogation |
| `ASI03-IMPERSONATION` | ASI03 Identity & Privilege Abuse | HIGH | Supervisor impersonation via forged inter-agent messages |
| `ASI04-TOOL-POISONING` | ASI04 Supply Chain Vulnerabilities | CRITICAL | Tool poisoning via adversarial tool descriptions |
| `ASI04-DEPENDENCY-INJECT` | ASI04 Supply Chain Vulnerabilities | HIGH | Dependency injection via adversarial external data |
| `ASI05-CODE-INJECTION` | ASI05 Output & Impact Control Failures | CRITICAL | Dangerous code generation via crafted prompt |
| `ASI05-SANDBOX-ESCAPE` | ASI05 Output & Impact Control Failures | CRITICAL | Sandbox escape via system resource access in generated code |
| `ASI06-MEMORY-POISON` | ASI06 Memory & Context Manipulation | HIGH | Memory content injection via adversarial instructions |
| `ASI06-CONTEXT-LEAK` | ASI06 Memory & Context Manipulation | HIGH | Cross-session context leak via unscoped memory |
| `ASI07-ORCHESTRATOR-HIJACK` | ASI07 Multi-Agent Orchestration Exploitation | CRITICAL | Orchestrator hijacking via authority claims |
| `ASI07-MSG-TAMPER` | ASI07 Multi-Agent Orchestration Exploitation | HIGH | Inter-agent message tampering |
| `ASI08-CASCADE-TRIGGER` | ASI08 Uncontrolled Autonomous Execution | HIGH | Cascading failure via error propagation |
| `ASI08-RESOURCE-EXHAUST` | ASI08 Uncontrolled Autonomous Execution | MEDIUM | Resource exhaustion via unbounded task expansion |
| `ASI09-AUTHORITY-SPOOF` | ASI09 Human-Agent Trust Exploitation | HIGH | Authority spoofing via false verification claims |
| `ASI09-CONFIRMATION-BYPASS` | ASI09 Human-Agent Trust Exploitation | HIGH | Confirmation gate bypass via claimed pre-approval |
| `ASI10-COVERT-EXFIL` | ASI10 Rogue Agent Behavior | CRITICAL | Covert exfiltration via steganographic output encoding |
| `ASI10-OBJECTIVE-DIVERGE` | ASI10 Rogue Agent Behavior | CRITICAL | Rogue behavior via hidden competing objectives |

---

## Scan Modes

### Offline mode (default)

No API keys required. Uses marker-based detection. Fast — a full scan completes in under a second.

```bash
agentsec scan --adapter langgraph --target ./my_graph.py
```

### Smart mode

LLM-powered attack payload generation and semantic response analysis via [OpenRouter](https://openrouter.ai). Produces richer, more context-aware findings.

```bash
export AGENTSEC_OPENROUTER_API_KEY=sk-or-...
agentsec scan --smart --adapter langgraph --target ./my_graph.py
```

Smart mode shows token usage and cost at the end of the scan. Use `--model` to choose the attacker model (default: `anthropic/claude-sonnet-4.6`).

---

## Web Dashboard

```bash
agentsec serve
```

Opens a web UI at `http://localhost:8457` with:

- **Live scan progress** — real-time probe status as scans run
- **Scan history** — browse and compare past scan results
- **Finding overrides** — mark false positives, add analyst notes
- **Export** — download results as Markdown, JSON, or SARIF

<!-- SCREENSHOT: dashboard-overview.png — web dashboard showing a completed scan with the summary table, findings list, and export buttons visible -->

---

## Guardrails

Defensive components that implement the patterns recommended by probe remediations. Drop them into your LangGraph graph as callbacks or use them standalone.

| Guardrail | Defends Against | OWASP |
|-----------|----------------|-------|
| `InputBoundaryEnforcer` | Prompt injection via tool output / user input | ASI01 |
| `CredentialIsolator` | Credential leakage in agent context | ASI03 |
| `CircuitBreaker` | Cascading failures across agents | ASI05 |
| `ExecutionLimiter` | Unbounded execution loops / resource exhaustion | ASI08 |

```python
from agentsec.guardrails import InputBoundaryEnforcer, CredentialIsolator

# Use as a LangGraph callback
graph = workflow.compile(callbacks=[InputBoundaryEnforcer()])

# Use standalone
enforcer = InputBoundaryEnforcer()
safe_input = enforcer.sanitize(user_input)
```

---

## Real-World Targets

agentsec ships adapter harnesses for 6 open-source LangGraph multi-agent projects. Use them to run agentsec against realistic systems in CI without any external API calls.

| Target | Architecture | Key Attack Surfaces |
|--------|-------------|-------------------|
| `langgraph-supervisor` | Supervisor + workers with handoff tools | Supervisor trust, tool delegation |
| `langgraph-swarm` | Swarm with dynamic agent handoffs | Agent identity in handoffs, shared memory |
| `multi-agent-rag-customer-support` | Travel booking RAG with safe/sensitive tools | RAG poisoning, tool privilege separation |
| `langgraph-email-automation` | Email categorization + RAG response drafting | Email injection, RAG manipulation |
| `rag-research-agent` | Research RAG with researcher subgraph | Subgraph isolation, retriever manipulation |
| `MultiAgenticRAG` | RAG with hallucination checks | Bypassing hallucination guards |

```bash
# Install target dependencies
uv sync --extra targets

# Run against a real-world harness
agentsec scan --adapter langgraph --target langgraph_supervisor_vulnerable
```

---

## CI Integration

agentsec outputs SARIF 2.1.0, the standard format for CI/CD security findings. GitHub, GitLab, and most CI tools consume SARIF natively.

```bash
agentsec scan --adapter langgraph --target ./src/agent.py \
  --format sarif --output results.sarif
```

**GitHub Actions — upload to Security tab:**

```yaml
- name: Run agentsec
  run: |
    agentsec scan --adapter langgraph --target ./src/agent.py \
      --format sarif --output results.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

See [`examples/ci_integration.yml`](examples/ci_integration.yml) for the complete workflow.

<!-- SCREENSHOT: github-security-tab.png — GitHub Security tab showing agentsec SARIF findings alongside CodeQL results, with severity badges and remediation details visible -->

---

## Output Formats

```bash
agentsec scan ... --format markdown    # default — human-readable report
agentsec scan ... --format json        # machine-readable with metadata envelope
agentsec scan ... --format sarif       # SARIF 2.1.0 for CI/CD integration
agentsec scan ... --output results.sarif   # write to file instead of stdout
```

Re-generate a report from a saved JSON file:

```bash
agentsec report --input findings.json --format sarif --output results.sarif
```

---

## Writing Custom Probes

Drop a new file in `src/agentsec/probes/asi<NN>_<name>/` — agentsec auto-discovers it, no registration needed.

```python
from agentsec.core.finding import Evidence, Finding, FindingStatus, OWASPCategory, Remediation, Severity
from agentsec.core.probe_base import BaseProbe, ProbeMetadata


class MyProbe(BaseProbe):
    def metadata(self) -> ProbeMetadata:
        return ProbeMetadata(
            id="ASI02-MY-PROBE",
            name="My Custom Probe",
            category=OWASPCategory.ASI02,
            default_severity=Severity.HIGH,
            description="Tests for a specific vulnerability pattern.",
        )

    def remediation(self) -> Remediation:
        return Remediation(
            summary="Apply the appropriate fix.",
            code_before="# vulnerable pattern",
            code_after="# fixed pattern",
        )

    async def attack(self, adapter) -> Finding:
        response = await adapter.invoke_graph(
            {"messages": [("human", "your attack payload")]}
        )
        status = FindingStatus.VULNERABLE if "marker" in str(response) else FindingStatus.RESISTANT
        return Finding(
            probe_id=self.metadata().id,
            probe_name=self.metadata().name,
            category=self.metadata().category,
            status=status,
            severity=self.metadata().default_severity,
            description=self.metadata().description,
            remediation=self.remediation(),
        )
```

---

## CLI Reference

```bash
agentsec scan --adapter langgraph --target ./graph.py         # Full scan
agentsec scan --adapter langgraph --target ./graph.py --smart # Smart mode (LLM-powered)
agentsec probe ASI01-INDIRECT-INJECT --target ./graph.py      # Single probe
agentsec probes list                                           # List all 20 probes
agentsec probes list --category ASI01                         # Filter by category
agentsec report --input findings.json --format sarif          # Re-generate report
agentsec serve                                                 # Launch web dashboard
```

---

## Contributing

```bash
git clone https://github.com/n3pt7un/agentsec
cd agentsec
uv sync
uv run pytest          # run tests
uv run ruff check src/ tests/  # lint
```

Contributions are welcome. Please open an issue before submitting a PR that adds new probes or changes the data model.

## License

MIT
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "DOCS: full README rewrite documenting all Phase 2 capabilities"
```

---

## Pass 3: Packaging + Release

---

### Task 7: Rename package and bump version

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/agentsec/__init__.py`

- [ ] **Step 1: Update pyproject.toml**

Replace the `[project]` section:

```toml
[project]
name = "agentsec-framework"
version = "1.0.0b1"
description = "Red-team and harden multi-agent LLM systems"
requires-python = ">=3.12"
license = "MIT"
classifiers = [
    "Development Status :: 4 - Beta",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
]
keywords = ["llm", "security", "agents", "owasp", "red-team", "multi-agent"]
```

Also remove any `anthropic` optional dependency group if present. Keep the `smart` extra as-is (it uses `openai>=1.0` for OpenRouter).

- [ ] **Step 2: Bump `__version__`**

In `src/agentsec/__init__.py`, replace:
```python
__version__ = "0.1.0"
```
With:
```python
__version__ = "1.0.0b1"
```

- [ ] **Step 3: Run full test suite**

```bash
uv run pytest -x -q
```

Expected: All tests pass. (The version string appears in SARIF output — the SARIF test only checks that `version` key exists, not its value, so this is safe.)

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml src/agentsec/__init__.py
git commit -m "ENH: rename package to agentsec-framework, bump version to 1.0.0b1"
```

---

### Task 8: Add publish workflow

**Files:**
- Create: `.github/workflows/publish.yml`

The CI workflow (`.github/workflows/ci.yml`) already exists and covers push/PR testing. Just add the publish workflow.

- [ ] **Step 1: Create the publish workflow**

```yaml
name: Publish to PyPI

on:
  workflow_dispatch:
    inputs:
      dry_run:
        description: "Dry run — build only, do not publish"
        required: false
        default: "false"
        type: choice
        options:
          - "false"
          - "true"

jobs:
  publish:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v4

      - name: Set up Python 3.12
        run: uv python install 3.12

      - name: Install dependencies
        run: uv sync --all-extras

      - name: Run tests
        run: uv run pytest -v

      - name: Build
        run: uv build

      - name: Publish to PyPI
        if: ${{ inputs.dry_run == 'false' }}
        env:
          UV_PUBLISH_TOKEN: ${{ secrets.PYPI_TOKEN }}
        run: uv publish
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/publish.yml
git commit -m "FEAT: add manual PyPI publish workflow"
```

---

### Task 9: Build verification

- [ ] **Step 1: Run full test suite**

```bash
uv run pytest -v 2>&1 | tail -10
```

Expected: All tests pass, no failures.

- [ ] **Step 2: Lint check**

```bash
uv run ruff check src/ tests/
```

Expected: No output (clean).

- [ ] **Step 3: Build the package**

```bash
uv build
```

Expected: Creates `dist/agentsec_framework-1.0.0b1-py3-none-any.whl` and `dist/agentsec_framework-1.0.0b1.tar.gz`.

- [ ] **Step 4: Verify wheel metadata**

```bash
unzip -p dist/agentsec_framework-1.0.0b1-py3-none-any.whl "*/METADATA" | grep -E "^(Name|Version):"
```

Expected output:
```
Name: agentsec-framework
Version: 1.0.0b1
```

- [ ] **Step 5: Final commit and report**

```bash
git add dist/ 2>/dev/null || true  # dist/ is gitignored, this is a no-op
git status
```

Report back to user: all three passes complete, tests pass, lint clean, wheel verified. Ask user for screenshots to finalize README (three images needed: terminal-scan.png, dashboard-overview.png, github-security-tab.png).
