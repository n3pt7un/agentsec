# agentsec

> Red-team and harden multi-agent LLM systems against OWASP Agentic Top 10

[![PyPI](https://img.shields.io/pypi/v/agentsec-framework)](https://pypi.org/project/agentsec-framework/)
[![Tests](https://img.shields.io/github/actions/workflow/status/n3pt7un/agentsec/ci.yml?label=tests)](https://github.com/n3pt7un/agentsec/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Wiki](https://img.shields.io/badge/docs-wiki-blue)](https://github.com/n3pt7un/agentsec/wiki)

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

Smart mode shows token usage and estimated cost at the end of each scan. Use `--model` to choose the attacker model (default: `anthropic/claude-sonnet-4.6`).

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

## Documentation

Full documentation is available on the [GitHub wiki](https://github.com/n3pt7un/agentsec/wiki):

- **[Using agentsec](https://github.com/n3pt7un/agentsec/wiki/Installation)** — installation, scan modes, CLI reference, CI integration, guardrails, web dashboard
- **[Developing agentsec](https://github.com/n3pt7un/agentsec/wiki/Architecture)** — architecture, probe authoring, adapter authoring, testing guide
- **[Reference](https://github.com/n3pt7un/agentsec/wiki/Probe-Index)** — probe index, API reference, OWASP categories, CLI commands

---

## Contributing

```bash
git clone https://github.com/n3pt7un/agentsec
cd agentsec
uv sync
uv run pytest                    # run tests
uv run ruff check src/ tests/    # lint
```

Contributions are welcome. Please open an issue before submitting a PR that adds new probes or changes the data model.

## License

MIT
