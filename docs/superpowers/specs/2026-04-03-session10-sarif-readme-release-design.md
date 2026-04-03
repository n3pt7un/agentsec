---
title: Session 10 — SARIF Reporter, README Rewrite, v1.0.0b1 Release
date: 2026-04-03
status: approved
---

# Session 10: SARIF Reporter + README Rewrite + v1.0.0b1 Release

## Goal

Ship three independent deliverables that complete Phase 2:

1. **SARIF reporter** — standard CI/CD output format for GitHub Security tab integration
2. **README rewrite** — full documentation of all Phase 2 capabilities
3. **Packaging + release** — rename to `agentsec-framework`, tag `v1.0.0b1`, add publish workflow

These are implemented as three sequential passes, each with its own verification checkpoint.

---

## Pass 1: SARIF Reporter

### New file: `src/agentsec/reporters/sarif.py`

Single public function:

```python
def generate_sarif(result: ScanResult) -> str:
    """Generate SARIF 2.1.0 JSON from a ScanResult."""
```

**SARIF structure:**

```
$schema: https://json.schemastore.org/sarif-2.1.0.json
version: 2.1.0
runs[0]:
  tool.driver:
    name: agentsec
    version: __version__
    informationUri: https://github.com/n3pt7un/agentsec
    rules: [ one per unique probe_id across ALL findings (all statuses) ]
  results: [ one per VULNERABLE or PARTIAL finding only ]
```

`rules` covers every probe that ran (including RESISTANT) so the tool inventory is complete.
`results` covers only actionable findings — RESISTANT probes produce no SARIF result.

**Rule shape** (one per probe that appears in findings):
```json
{
  "id": "ASI01-INDIRECT-INJECT",
  "name": "IndirectPromptInjection",
  "shortDescription": { "text": "<probe_name>" },
  "helpUri": "https://github.com/n3pt7un/agentsec",
  "properties": { "tags": ["<category_value>"] }
}
```

**Result shape** (one per VULNERABLE/PARTIAL finding):
```json
{
  "ruleId": "<probe_id>",
  "level": "error|warning|note",
  "message": { "text": "<description>\n\nRemediation: <remediation.summary>" },
  "locations": [{
    "logicalLocations": [{ "name": "<probe_id>" }],
    "physicalLocation": {
      "artifactLocation": { "uri": "agent://<evidence.target_agent or 'unknown'>" }
    }
  }]
}
```

**Severity mapping:**
| Finding severity | SARIF level |
|-----------------|-------------|
| critical, high  | error       |
| medium          | warning     |
| low, info       | note        |

**RESISTANT findings are excluded** — SARIF results represent issues, not clean checks.

### CLI changes: `src/agentsec/cli/main.py`

Both `scan` and `report` commands: extend `--format` option to accept `"sarif"` as a third value alongside `"markdown"` and `"json"`. Add a third branch in the report generation block importing `generate_sarif`.

### Dashboard changes: `src/agentsec/dashboard/routes/scans.py`

Two endpoints gain `sarif` support:

- `GET /scans/{scan_id}/export?format=sarif` — returns `application/sarif+json`, filename `scan-{scan_id}.sarif`
- `POST /scans/export` — `ExportRequest.format` type extended from `Literal["md", "json"]` to `Literal["md", "json", "sarif"]`; zip archive includes `.sarif` files

### CI example: `examples/ci_integration.yml`

GitHub Actions workflow demonstrating SARIF upload to GitHub Security tab:

```yaml
name: Agent Security Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
      - run: uv pip install agentsec-framework
      - run: agentsec scan --adapter langgraph --target ./src/agent.py --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Tests: `tests/test_reporters/test_sarif.py`

Build a synthetic `ScanResult` with:
- One VULNERABLE/critical finding with evidence
- One RESISTANT finding (should be excluded from SARIF results)

Assert:
- Top-level schema keys present (`$schema`, `version`, `runs`)
- `runs[0].tool.driver.name == "agentsec"`
- `rules` has exactly 2 entries (one per probe that ran, regardless of status)
- `results` has exactly 1 entry (only the VULNERABLE finding)
- `results[0].level == "error"` (critical → error)
- `results[0].locations[0].physicalLocation.artifactLocation.uri` starts with `"agent://"`
- RESISTANT finding is absent from results

---

## Pass 2: README Rewrite

Full rewrite of `README.md`. Structure and content:

### Badges
```
PyPI: agentsec-framework | Tests: CI workflow | License: MIT
```

### Quick Start
```bash
pip install agentsec-framework
agentsec scan --adapter langgraph --target ./my_graph.py
```
Short terminal snippet showing the live Rich dashboard (text representation, not screenshot).

### What It Tests
Full table of all 20 probes:

| Probe ID | OWASP Category | Severity | Description |
Populated from the actual probe registry output — all ASI01–ASI10 probes.

### Scan Modes

**Offline mode** (default): No API keys required. Marker-based detection. Fast.
```bash
agentsec scan --adapter langgraph --target ./my_graph.py
```

**Smart mode**: LLM-powered payload generation and semantic detection via OpenRouter. Shows token cost.
```bash
AGENTSEC_OPENROUTER_API_KEY=sk-... agentsec scan --smart --target ./my_graph.py
```

### Web Dashboard
```bash
agentsec serve
```
Brief description of capabilities (live scan progress, scan history, finding overrides, export).

`<!-- SCREENSHOT: dashboard-overview.png — full dashboard with a scan in progress -->`

### Guardrails

Defensive components that implement the remediations recommended by probes:

| Guardrail | Defends Against | OWASP |
|-----------|----------------|-------|
| `InputBoundaryEnforcer` | Prompt injection via tool output/user input | ASI01 |
| `CredentialIsolator` | Credential leakage in agent context | ASI03 |
| `CircuitBreaker` | Cascading failures across agents | ASI05 |
| `ExecutionLimiter` | Unbounded execution loops | ASI08 |

Import snippet showing standalone and LangGraph callback usage.

### Real-World Targets
Table of 6 adapter harnesses with install and run commands.

### CI Integration
SARIF section with the `examples/ci_integration.yml` snippet and a note about GitHub Security tab.

`<!-- SCREENSHOT: github-security-tab.png — GitHub Security tab showing agentsec SARIF findings -->`

### Output Formats
```
--format markdown   # default, human-readable
--format json       # machine-readable
--format sarif      # CI/CD integration
--output results.sarif
```

Also: export from dashboard UI.

### Contributing
```bash
uv sync
uv run pytest
uv run ruff check src/ tests/
```

### Screenshot placeholders
Three labeled placeholders in the README:
1. `<!-- SCREENSHOT: terminal-scan.png — terminal showing Rich live dashboard during a scan -->`
2. `<!-- SCREENSHOT: dashboard-overview.png — web dashboard with scan results loaded -->`
3. `<!-- SCREENSHOT: github-security-tab.png — GitHub Security tab with SARIF findings uploaded -->`

After the README is written, user will be asked for these three screenshots before the README is finalized.

---

## Pass 3: Packaging + Release

### `pyproject.toml` changes

```toml
name = "agentsec-framework"
version = "1.0.0b1"

classifiers = [
    "Development Status :: 4 - Beta",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
]

keywords = ["llm", "security", "agents", "owasp", "red-team", "multi-agent"]
```

Remove any `anthropic` optional dependency references. OpenRouter (`openai>=1.0` under the `smart` extra) is the only LLM provider.

### `src/agentsec/__init__.py`

```python
__version__ = "1.0.0b1"
```

### `.github/workflows/publish.yml` (new)

Manual trigger only (`workflow_dispatch`). Steps:
1. `actions/checkout@v4`
2. `astral-sh/setup-uv@v4`
3. `uv build`
4. `uv publish` using `PYPI_TOKEN` repository secret

Also add `.github/workflows/ci.yml` if it doesn't already exist — runs `uv run pytest` and `uv run ruff check src/ tests/` on push and PR to `main`.

### Verification gate

Before tagging:
- `uv run pytest -v` — all tests pass
- `uv run ruff check src/ tests/` — clean
- `uv build` — produces clean wheel and sdist
- `unzip -p dist/agentsec_framework-1.0.0b1-*.whl METADATA | grep -E "^Name:|^Version:"` confirms `agentsec-framework 1.0.0b1`

### Git tag

`v1.0.0b1` — user applies after review. The publish workflow is triggered manually from GitHub UI.

---

## Implementation Order

1. Pass 1: SARIF reporter → tests → CLI wire-up → dashboard wire-up → CI example → ruff → pytest
2. Pass 2: README rewrite → screenshot placeholder review with user
3. Pass 3: pyproject rename → version bump → GitHub workflows → `uv build` verification

Each pass ends with `uv run pytest -v` and `uv run ruff check src/ tests/` clean before proceeding.
