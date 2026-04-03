# agentsec

> Red-team and harden multi-agent LLM systems against OWASP Agentic Top 10

agentsec probes your multi-agent LLM system for vulnerabilities, scores findings against the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), and generates actionable remediation reports with copy-pasteable fixes.

**Break your agents. Fix the holes. Ship with confidence.**

---

## Which section do you need?

```mermaid
flowchart TD
    A([Start here]) --> B{What do you want to do?}
    B -->|Run agentsec against my agents| C[Using agentsec]
    B -->|Write probes or adapters| D[Developing agentsec]
    B -->|Look up a class or command| E[Reference]
    C --> C1["[Installation](using/Installation)"]
    C --> C2["[Quick Start](using/Quick-Start)"]
    C --> C3["[Guardrails](using/Guardrails)"]
    D --> D1["[Architecture](developing/Architecture)"]
    D --> D2["[Probe Authoring](developing/Probe-Authoring)"]
    D --> D3["[Contributing](developing/Contributing)"]
    E --> E1["[Probe Index](reference/Probe-Index)"]
    E --> E2["[CLI Commands](reference/CLI-Commands)"]
    E --> E3["[OWASP Categories](reference/OWASP-Categories)"]
```

---

## Using agentsec

For security engineers and DevSecOps teams running agentsec against their own systems.

| | |
|--|--|
| **[Installation](using/Installation)** | pip, uv, extras, env vars |
| **[Quick Start](using/Quick-Start)** | First scan in three commands |
| **[Scan Modes](using/Scan-Modes)** | Offline vs Smart mode |
| **[Probe Selector](using/Probe-Selector)** | Filter by probe ID, category, or severity |
| **[CLI Reference](using/CLI-Reference)** | All commands and flags |
| **[Output Formats](using/Output-Formats)** | Markdown, JSON, SARIF |
| **[CI Integration](using/CI-Integration)** | GitHub Actions, GitLab CI |
| **[Guardrails](using/Guardrails)** | Drop-in defensive components |
| **[Web Dashboard](using/Web-Dashboard)** | `agentsec serve` UI walkthrough |
| **[Real-World Targets](using/Real-World-Targets)** | 6 bundled harnesses |

---

## Developing agentsec

For contributors writing new probes, adapters, or framework components.

| | |
|--|--|
| **[Architecture](developing/Architecture)** | System overview and data flow |
| **[Probe Authoring](developing/Probe-Authoring)** | Write a new probe end-to-end |
| **[Adapter Authoring](developing/Adapter-Authoring)** | Write a new framework adapter |
| **[LLM Integration](developing/LLM-Integration)** | LLMProvider, OpenRouter, offline fallback |
| **[Detection Pipeline](developing/Detection-Pipeline)** | Marker vs semantic detection |
| **[Dashboard Internals](developing/Dashboard-Internals)** | FastAPI, SSE, ScanManager |
| **[Testing Guide](developing/Testing-Guide)** | pytest-asyncio, fixtures, mocking |
| **[Contributing](developing/Contributing)** | Dev setup, commit style, PR workflow |

---

## Reference

| | |
|--|--|
| **[Probe Index](reference/Probe-Index)** | All 20 probes — ID, category, severity |
| **[OWASP Categories](reference/OWASP-Categories)** | All 10 ASI categories |
| **[API: BaseProbe](reference/API-BaseProbe)** | Probe base class and ProbeMetadata |
| **[API: BaseAdapter](reference/API-BaseAdapter)** | Adapter interface |
| **[API: Finding](reference/API-Finding)** | Finding, Evidence, Remediation models |
| **[API: ScanConfig](reference/API-ScanConfig)** | Scan configuration |
| **[API: LLMProvider](reference/API-LLMProvider)** | LLM provider interface |
| **[API: Guardrails](reference/API-Guardrails)** | All four guardrail classes |
| **[API: Reporters](reference/API-Reporters)** | Markdown, JSON, SARIF reporters |
| **[CLI Commands](reference/CLI-Commands)** | Full flag reference |
