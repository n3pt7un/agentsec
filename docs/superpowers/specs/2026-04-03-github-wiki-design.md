---
name: GitHub Wiki — agentsec
description: Design spec for the agentsec GitHub wiki — structure, content, generation scripts, and CI delivery
type: spec
---

# GitHub Wiki Design — agentsec

## Overview

A comprehensive GitHub wiki covering both tool usage (security practitioners) and framework development (contributors). Wiki pages live source-controlled in `wiki/` inside the main repo and are pushed to the GitHub wiki on every merge to `main` via CI. Reference pages are partially auto-generated from probe registry metadata, docstrings, and Typer CLI introspection.

---

## Goals

- Give security practitioners everything needed to install, configure, and use agentsec without reading source code
- Give contributors everything needed to write probes, adapters, and tests without reading source code
- Provide a full public API reference for all public classes and interfaces
- Keep reference content in sync with code automatically via generation scripts
- Use Mermaid diagrams wherever a visual representation aids understanding

---

## Repository Layout

```
wiki/
├── Home.md                    # Landing page — tagline, summary, nav decision tree
├── _Sidebar.md                # GitHub wiki sidebar
│
├── using/
│   ├── Installation.md
│   ├── Quick-Start.md
│   ├── Scan-Modes.md
│   ├── CLI-Reference.md
│   ├── Output-Formats.md
│   ├── CI-Integration.md
│   ├── Guardrails.md
│   ├── Web-Dashboard.md
│   ├── Real-World-Targets.md
│   └── Probe-Selector.md
│
├── developing/
│   ├── Architecture.md
│   ├── Probe-Authoring.md
│   ├── Adapter-Authoring.md
│   ├── LLM-Integration.md
│   ├── Detection-Pipeline.md
│   ├── Dashboard-Internals.md
│   ├── Testing-Guide.md
│   └── Contributing.md
│
└── reference/
    ├── Probe-Index.md          # AUTO-GENERATED
    ├── API-BaseProbe.md        # AUTO-GENERATED
    ├── API-BaseAdapter.md      # AUTO-GENERATED
    ├── API-Finding.md          # AUTO-GENERATED
    ├── API-ScanConfig.md       # AUTO-GENERATED
    ├── API-LLMProvider.md      # AUTO-GENERATED
    ├── API-Guardrails.md       # AUTO-GENERATED
    ├── API-Reporters.md        # AUTO-GENERATED
    ├── OWASP-Categories.md     # Handwritten
    └── CLI-Commands.md         # AUTO-GENERATED
```

The `wiki/` directory is committed to the main repo. CI pushes its contents to the GitHub wiki remote on every merge to `main`. Handwritten pages coexist with generated pages — generation scripts only overwrite the files marked `AUTO-GENERATED`.

---

## Section 1: Using agentsec

Target audience: security engineers and DevSecOps teams who install and run agentsec against their own agent systems.

### Home.md

- Project tagline and one-paragraph summary
- Mermaid flowchart: "Which section do you need?" — branches to Using / Developing / Reference based on user role
- Quick links to all three top-level sections

### Installation.md

- `pip install agentsec-framework` and `uv add agentsec-framework`
- Optional extras: `[smart]` (OpenRouter LLM), `[targets]` (real-world harnesses)
- Required environment variables (`AGENTSEC_OPENROUTER_API_KEY` for smart mode)
- Verify install: `agentsec --version` and `agentsec probes list`
- Python version requirement (3.12+)

### Quick-Start.md

- Three commands from zero to first scan result
- Annotated terminal output showing what each section of the output means
- Link to Scan-Modes for next steps

### Scan-Modes.md

- **Offline mode** (default): marker-based detection, no API keys, sub-second full scans
- **Smart mode**: LLM-powered payload generation + semantic detection via OpenRouter, richer findings, usage cost display
- When to use each: offline for CI speed, smart for depth
- `--model` flag — supported model IDs, cost implications
- Token usage summary format explained

### CLI-Reference.md

- All top-level commands: `scan`, `probe`, `probes`, `report`, `serve`
- Every flag with type, default, and example
- Exit codes and what they mean
- Environment variable overrides for all flags

### Output-Formats.md

- `markdown` (default): structure of the human-readable report
- `json`: envelope structure, all fields, how to parse findings programmatically
- `sarif`: SARIF 2.1.0 structure, rule IDs, how severity maps to SARIF level
- `--output` flag: write to file vs stdout
- `agentsec report --input findings.json`: re-generating a report from saved JSON

### CI-Integration.md

- **GitHub Actions**: full workflow YAML, SARIF upload to Security tab, badge setup
- **GitLab CI**: `.gitlab-ci.yml` snippet with artifact upload
- **Generic shell**: exit code handling for pass/fail gates
- Recommended: run offline mode in CI for speed, smart mode nightly for depth
- Copy-paste ready — no placeholders, real working examples

### Guardrails.md

For each of the 4 guardrails (`InputBoundaryEnforcer`, `CredentialIsolator`, `CircuitBreaker`, `ExecutionLimiter`):
- What vulnerability it defends against (OWASP category)
- Usage as a LangGraph callback
- Usage as a standalone wrapper
- All constructor arguments and defaults
- Code examples for both usage patterns

### Web-Dashboard.md

- `agentsec serve` — what it starts, default port (8457), how to change it
- **Live scan progress** panel: probe status, real-time updates via SSE
- **Scan history** panel: browsing past results, comparison view
- **Finding overrides**: marking false positives, adding analyst notes
- **Export panel**: downloading Markdown, JSON, SARIF from the UI
- Screenshot placeholders for each panel (to be filled with actual screenshots)

### Real-World-Targets.md

For each of the 6 bundled harnesses:
- What the target is (project name, architecture summary)
- Install command (`uv sync --extra targets`)
- Scan command
- Key attack surfaces and which probes hit them
- Expected findings (what a clean vs vulnerable system looks like)

### Probe-Selector.md

- `--probe ASI01-INDIRECT-INJECT` — run a single probe
- `--category ASI01` — run all probes for a category
- `--severity critical` — filter by minimum severity
- Probe ID naming convention: `ASI<NN>-<SLUG>`
- How to combine filters
- Link to Probe-Index reference page

---

## Section 2: Developing agentsec

Target audience: contributors writing new probes, adapters, or framework components.

### Architecture.md

- **System overview Mermaid diagram**: all components (CLI, Scanner, Registry, Probes, Adapters, LLM, Reporters, Dashboard) and their relationships
- **Data flow diagram**: CLI invocation → Scanner → probe loop → findings → reporter → output
- Component responsibility summary table
- Key design principles (from CLAUDE.md) explained with rationale
- Module dependency rules (what imports what, what never imports what)

### Probe-Authoring.md

- **Probe lifecycle Mermaid diagram**: Registry discovery → instantiation → `metadata()` → `attack(adapter)` → `Finding` → Reporter
- Step-by-step: create the directory, create the file, implement all three methods
- `ProbeMetadata` fields — all required, all optional
- `Remediation` fields — `summary`, `code_before`, `code_after` — with examples
- `Finding` construction — status, severity, evidence
- How to use `adapter.invoke_graph()` and `adapter.get_agent_targets()`
- How to use `LLMProvider` for payload generation and detection (smart mode)
- Auto-discovery: file naming rules, no registration needed
- Writing the test: fixture graph, expected `FindingStatus`
- Common mistakes and anti-patterns

### Adapter-Authoring.md

- **Adapter ↔ probe ↔ scanner interaction Mermaid diagram**
- `BaseAdapter` abstract interface — all methods, their contracts, what they must return
- How adapters are selected at runtime (adapter name → class lookup)
- The LangGraph adapter as reference implementation: how `invoke_graph()` wraps the graph call, how `get_agent_targets()` discovers agents
- Writing a minimal HTTP adapter skeleton (step-by-step)
- Registration: how to make a new adapter discoverable
- Testing: how to mock the target system

### LLM-Integration.md

- `LLMProvider` abstract interface: `generate()` and `classify()` method contracts
- `OpenRouterProvider`: auth, model selection, retry logic, token tracking
- `OfflineProvider`: always available, returns hardcoded payloads, no API needed
- How probes call the provider — injected via `ScanConfig`, not imported directly
- Payload generation pattern vs classification pattern
- Adding a new provider: what to implement, how to register it

### Detection-Pipeline.md

- **Decision flow Mermaid diagram**: for each probe response — marker match? → semantic classify? → `FindingStatus`
- Marker-based detection: how markers are defined, how responses are scanned
- Semantic detection (smart mode): the classification prompt, how `FindingStatus` is set from LLM output
- Confidence and evidence: how `Evidence` objects are constructed
- How to write a probe that supports both detection modes

### Dashboard-Internals.md

- **Scan state machine Mermaid diagram**: IDLE → RUNNING → COMPLETED / FAILED
- **SSE broadcast topology diagram**: `ScanManager` → `ScanStore` → SSE route → browser
- FastAPI app structure: routes, lifespan, CORS
- `ScanStore`: in-memory scan state, how it's read/written
- `ScanManager`: async scan execution, probe ordering, progress emission
- `ScanStore` finding override mechanism
- How the frontend consumes SSE events (event types and payload shapes)

### Testing-Guide.md

- pytest-asyncio configuration (`asyncio_mode = "auto"`)
- Fixture graphs in `tests/fixtures/` — what each provides, how to use them in probe tests
- Mocking `LLMProvider` for deterministic tests
- Running the full suite: `uv run pytest`
- Running against real targets locally (with and without API keys)
- Test naming conventions and file organization
- What to test in a new probe: VULNERABLE path, RESISTANT path, ERROR path

### Contributing.md

- Dev environment setup: `uv sync`, `uv run agentsec --help` to verify
- Commit style: `FEAT/ENH/BUG/MAINT/TEST/DOCS/REFACTOR: message`
- PR workflow: open issue first for new probes or data model changes
- Adding a new probe checklist: directory, file, metadata, remediation, test, verify auto-discovery
- Code style: ruff, Google docstrings, async-first, no bare `except:`, no `os.environ`
- Running lint: `uv run ruff check src/ tests/`

---

## Section 3: Reference

Target audience: both users and developers looking up specific APIs or probe IDs.

### Probe-Index.md — AUTO-GENERATED

Generated by `scripts/wiki/generate_probe_index.py`. Reads the probe registry, calls `metadata()` on every probe, outputs a Markdown table:

| Probe ID | Category | Severity | Name | Description |
|----------|----------|----------|------|-------------|

One row per probe, sorted by category then ID. Includes OWASP category links.

### API-BaseProbe.md — AUTO-GENERATED

Generated by `scripts/wiki/generate_api_reference.py`. Extracts from `agentsec.core.probe_base`:
- `BaseProbe` class — class-level docstring, all abstract methods with signatures and docstrings
- `ProbeMetadata` — all fields with types, defaults, descriptions
- `ProbeResult` — if applicable

### API-BaseAdapter.md — AUTO-GENERATED

Extracts from `agentsec.adapters.base`:
- `BaseAdapter` — all abstract methods, contracts, return types

### API-Finding.md — AUTO-GENERATED

Extracts from `agentsec.core.finding`:
- `Finding` — all fields
- `Evidence` — all fields
- `Remediation` — all fields
- `Severity` — all enum values
- `FindingStatus` — all enum values
- `OWASPCategory` — all enum values

### API-ScanConfig.md — AUTO-GENERATED

Extracts from `agentsec.core.config`:
- `ScanConfig` — all fields, env var overrides, validation rules
- `ProbeFilter` — if applicable

### API-LLMProvider.md — AUTO-GENERATED

Extracts from `agentsec.llm.provider`:
- Abstract `LLMProvider` — all methods
- `OpenRouterProvider` — constructor args, model selection
- `OfflineProvider` — behavior description

### API-Guardrails.md — AUTO-GENERATED

Extracts from all four guardrail modules:
- `InputBoundaryEnforcer` — constructor, `sanitize()`, callback interface
- `CredentialIsolator` — constructor, public methods
- `CircuitBreaker` — constructor, trip conditions, reset behavior
- `ExecutionLimiter` — constructor, limit config, callback interface

### API-Reporters.md — AUTO-GENERATED

Extracts from all three reporter modules:
- `MarkdownReporter`, `JSONReporter`, `SARIFReporter` — constructor, `render()` contract

### OWASP-Categories.md — Handwritten

For each of the 10 ASI categories:
- Category name and OWASP description
- Example real-world attack scenario
- Which agentsec probes cover it (links to Probe-Index)
- Recommended guardrails and remediations

### CLI-Commands.md — AUTO-GENERATED

Generated by `scripts/wiki/generate_cli_reference.py`. Invokes `agentsec <command> --help` recursively, parses output, renders as structured Markdown tables with all flags, types, defaults, and descriptions.

---

## Generation Scripts

All scripts live in `scripts/wiki/`. They run as part of the CI wiki push job.

### `generate_probe_index.py`

```
1. Import ProbeRegistry from agentsec.probes.registry
2. Call registry.discover() to load all probes
3. For each probe: instantiate, call metadata()
4. Sort by category, then probe ID
5. Write wiki/reference/Probe-Index.md
```

No docstring parsing — all data comes from `ProbeMetadata` fields.

### `generate_api_reference.py`

```
1. Define target modules and classes to document
2. For each class: use inspect.getdoc() + ast parsing for field-level docs
3. Format as structured Markdown (class heading, method signatures, docstrings)
4. Write one file per API page into wiki/reference/
```

Dependency-free (stdlib only). Overwrites only the designated auto-generated files.

### `generate_cli_reference.py`

```
1. Run: agentsec --help, capture output
2. For each subcommand discovered: run agentsec <cmd> --help
3. Parse flag names, types, defaults, descriptions
4. Write wiki/reference/CLI-Commands.md as Markdown tables
```

---

## CI Pipeline

File: `.github/workflows/wiki.yml`

```yaml
name: Push wiki

on:
  push:
    branches: [main]

jobs:
  wiki:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync
      - run: python scripts/wiki/generate_probe_index.py
      - run: python scripts/wiki/generate_api_reference.py
      - run: python scripts/wiki/generate_cli_reference.py
      - uses: stefanzweifel/git-auto-commit-action@v5
        with:
          repository: wiki/
          commit_message: "chore: sync wiki from main"
          push_to_wiki: true
```

Handwritten pages are committed directly to `wiki/` in the main repo. The CI job runs the three generation scripts, then pushes the full `wiki/` directory to the GitHub wiki remote.

---

## Mermaid Diagram Locations

| Page | Diagram type | Content |
|------|-------------|---------|
| `Home.md` | Flowchart | "Which section do you need?" — user role → section |
| `Architecture.md` | Graph (LR) | All components and dependency arrows |
| `Architecture.md` | Sequence | CLI invocation → scan → report data flow |
| `Probe-Authoring.md` | Flowchart | Probe lifecycle: discovery → instantiation → attack → finding |
| `Adapter-Authoring.md` | Sequence | Adapter ↔ probe ↔ scanner interaction |
| `Detection-Pipeline.md` | Flowchart | Marker match → semantic classify → FindingStatus decision |
| `Dashboard-Internals.md` | State diagram | Scan state machine: IDLE → RUNNING → COMPLETED/FAILED |
| `Dashboard-Internals.md` | Sequence | SSE broadcast: ScanManager → ScanStore → SSE route → browser |

---

## Out of Scope

- A static site generator (MkDocs, Docusaurus) — GitHub wiki rendering is sufficient and avoids a build pipeline
- Versioned docs — a single wiki tracking `main` is appropriate at this stage
- Internationalization
- Interactive API explorer
