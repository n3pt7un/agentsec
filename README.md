# agentsec

> Red-team and harden multi-agent LLM systems against OWASP Agentic Top 10

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Phase 1](https://img.shields.io/badge/phase-1%20foundation-orange.svg)](#roadmap)

**Break your agents. Fix the holes. Ship with confidence.**

`agentsec` is an open-source Python framework that systematically red-teams multi-agent LLM systems, maps findings to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), and generates actionable remediation reports with copy-pasteable fixes.

---

## What it does

1. **Probe** — Attack a multi-agent system across OWASP ASI01–ASI10: goal hijacking, tool misuse, privilege escalation, memory poisoning, inter-agent manipulation, cascading failures.
2. **Score** — Report each vulnerability with severity, exploitability, and blast radius.
3. **Remediate** — For every finding, emit a concrete fix: guardrail code, config change, or architecture recommendation. Not "be more careful" — actual code.

## What it is NOT

- Not a single-model prompt injection tester ([garak](https://github.com/leondz/garak) and [promptfoo](https://github.com/promptfoo/promptfoo) already do this well)
- Not a pentesting tool that *uses* agents to attack things
- Not a runtime guardrail product

`agentsec` fills the gap: **a testing framework for systemic vulnerabilities that emerge when multiple agents interact**.

---

## Quick Start

```bash
pip install agentsec
agentsec scan --adapter langgraph --target ./my_graph.py
```

Or with `uv`:

```bash
uv add agentsec
uv run agentsec scan --adapter langgraph --target ./my_graph.py
```

### Run a single probe

```bash
agentsec probe ASI01-INDIRECT-INJECT --adapter langgraph --target ./my_graph.py --verbose
```

### List available probes

```bash
agentsec probes list
agentsec probes list --category ASI03
```

### Generate a report from saved findings

```bash
agentsec report --input findings.json --format markdown
agentsec report --input findings.json --format sarif   # for GitHub Security tab
```

---

## OWASP ASI01–ASI10 Coverage

| Category | Description | Probes |
|----------|-------------|--------|
| ASI01 | Agent Goal Hijacking | `INDIRECT-INJECT`, `ROLE-CONFUSION`, `CONTEXT-OVERFLOW`, `GOAL-DRIFT` |
| ASI02 | Tool Misuse & Exploitation | `PARAM-INJECTION`, `TOOL-CHAIN-ABUSE`, `SCHEMA-BYPASS`, `PRIV-TOOL-ACCESS` |
| ASI03 | Identity & Privilege Abuse | `IMPERSONATION`, `PRIV-ESCALATION`, `DELEGATION-ABUSE`, `CRED-EXTRACTION` |
| ASI04 | Supply Chain Vulnerabilities | `TOOL-POISONING`, `DEPENDENCY-INJECT`, `PROMPT-TEMPLATE-INJECT` |
| ASI05 | Output & Impact Control Failures | `CASCADE-TRIGGER`, `OUTPUT-AMPLIFY`, `IRREVERSIBLE-ACTION` |
| ASI06 | Memory & Context Manipulation | `MEMORY-POISON`, `CONTEXT-LEAK`, `RAG-POISON`, `HISTORY-REWRITE` |
| ASI07 | Orchestration Exploitation | `ROGUE-AGENT-INJECT`, `MSG-REPLAY`, `MSG-TAMPER`, `ORCHESTRATOR-HIJACK` |
| ASI08 | Uncontrolled Autonomous Execution | `INFINITE-LOOP`, `RESOURCE-EXHAUST`, `SCOPE-CREEP` |
| ASI09 | Human-Agent Trust Exploitation | `AUTHORITY-SPOOF`, `CONFIRMATION-BYPASS`, `FALSE-CONSENSUS` |
| ASI10 | Rogue Agent Behavior | `COVERT-EXFIL`, `OBJECTIVE-DIVERGE`, `COLLUDE` |

---

## Example Report Output

```
agentsec v0.1.0 — Scanning: supervisor_crew.py

 ┌─ Agents Discovered ─────────────────────────────────┐
 │ supervisor  → researcher, writer, reviewer           │
 │ researcher  → [web_search, arxiv_search]             │
 │ writer      → [file_write, format_doc]               │
 │ reviewer    → [approve, reject, request_edit]        │
 └──────────────────────────────────────────────────────┘

 ┌─ Scan Progress ──────────────────────────────────────┐
 │ ASI01 Goal Hijacking     ████████████░░  6/8  ⚠ 2   │
 │ ASI03 Identity Abuse     ████░░░░░░░░░░  1/4  🔴 1  │
 │ ASI06 Memory Manip.      ░░░░░░░░░░░░░░  0/4  ⏳    │
 └──────────────────────────────────────────────────────┘

 Elapsed: 1m 22s │ Probes: 7/16 │ Findings: 3
```

Each finding in the markdown report includes:
- Exact attack input and agent response (evidence)
- Severity, exploitability, and blast radius
- Copy-pasteable code fix with before/after diff
- OWASP reference links

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                     agentsec                          │
│                                                       │
│  ┌─────────┐   ┌──────────┐   ┌───────────────────┐  │
│  │ Probes  │ → │ Scanner  │ → │     Reporter      │  │
│  │(attacks)│   │ (runner) │   │(findings + fixes) │  │
│  └─────────┘   └──────────┘   └───────────────────┘  │
│       ↑               ↑                               │
│  ┌────┴────┐    ┌──────┴─────┐                        │
│  │  Probe  │    │  Adapters  │                        │
│  │ Library │    │ ┌────────┐ │                        │
│  │(OWASP)  │    │ │LangGraph│ │                       │
│  └─────────┘    │ ├────────┤ │                        │
│                 │ │Protocol│ │ ← framework-agnostic   │
│                 │ └────────┘ │                        │
│                 └────────────┘                        │
└──────────────────────────────────────────────────────┘
```

**Probes** are self-contained attack modules — each has attack logic, metadata, and remediation text. Drop a new file in the right directory and it's auto-discovered.

**Adapters** are the abstraction boundary between probes and target frameworks. Probes never import framework code.

**Findings** always include actionable remediations. Every finding ships with code.

---

## Installation

### With LangGraph support (recommended for Phase 1)

```bash
pip install "agentsec[langgraph]"
```

### With Anthropic SDK (for LLM-generated attack payloads)

```bash
pip install "agentsec[anthropic]"
```

### Full install

```bash
pip install "agentsec[langgraph,anthropic]"
```

Set `AGENTSEC_LLM_MODEL` and `ANTHROPIC_API_KEY` (or any provider) to enable LLM-generated payloads. Without an API key, probes fall back to hardcoded payload templates.

---

## Writing Custom Probes

Drop a file in `src/agentsec/probes/asiXX_your_category/your_probe.py`:

```python
from agentsec.core.probe_base import BaseProbe, ProbeMetadata
from agentsec.core.finding import Finding, FindingStatus, OWASPCategory, Severity, Remediation

class MyCustomProbe(BaseProbe):
    def metadata(self) -> ProbeMetadata:
        return ProbeMetadata(
            id="ASI01-MY-PROBE",
            name="My Custom Attack",
            category=OWASPCategory.ASI01,
            default_severity=Severity.HIGH,
            description="Tests whether...",
            tags=["injection", "custom"],
        )

    async def attack(self, adapter) -> Finding:
        agents = await adapter.discover()
        response = await adapter.send_message(agents[0].name, "malicious payload")
        # analyze response...
        return Finding(
            probe_id=self.metadata().id,
            probe_name=self.metadata().name,
            category=OWASPCategory.ASI01,
            status=FindingStatus.VULNERABLE,
            severity=Severity.HIGH,
            description="Agent followed injected instruction",
            remediation=self.remediation(),
        )

    def remediation(self) -> Remediation:
        return Remediation(
            summary="Enforce input boundaries",
            code_after='# sanitize tool outputs before passing to agent',
        )
```

That's it. The probe registry auto-discovers it on next run.

---

## Development

```bash
git clone https://github.com/yourusername/agentsec
cd agentsec
uv sync --extra dev --extra langgraph --extra anthropic
uv run pytest
uv run ruff check src/
```

---

## Roadmap

- **Phase 1** (current): Foundation + 6 probes (ASI01, ASI03, ASI06) + LangGraph adapter + Markdown reporter
- **Phase 2**: Full ASI01–ASI10 coverage + guardrails module + Protocol adapter + SARIF reporter + PyPI publish
- **Phase 3**: Web dashboard (FastAPI + React) + remediation tracker + community tooling

---

## Why This Exists

The OWASP Top 10 for Agentic Applications (2026) is now referenced by Microsoft, NVIDIA, and AWS. TrinityGuard found only 7.1% average safety pass rate across multi-agent systems. Agentic systems are moving to production faster than security tooling can keep up.

Existing tools (garak, promptfoo, PyRIT) test single-model I/O. None of them target the systemic vulnerabilities that emerge from **agent-to-agent interactions** — orchestration exploitation, memory poisoning across sessions, identity abuse in delegation chains.

`agentsec` is the missing tool.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) (coming in Phase 2). For now:
- Bug reports and feature requests: open a GitHub issue
- New probe ideas: open an issue with the probe ID format (`ASI0X-PROBE-NAME`) and attack strategy
- The best way to contribute is to write a probe for a category that's not yet covered

---

## License

MIT — see [LICENSE](LICENSE).
