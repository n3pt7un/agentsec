# Quick Start

Three commands from zero to first scan result.

## Step 1: Install

```bash
pip install agentsec-framework
```

## Step 2: Point agentsec at your agent graph

agentsec needs a Python file that exposes a compiled LangGraph graph. The `--target` argument is either:
- A path to a Python file exporting a compiled graph object
- The name of a bundled real-world harness (see [Real-World Targets](Real-World-Targets))

```bash
# Scan your own agent
agentsec scan --adapter langgraph --target ./my_agent.py

# Or use a bundled harness (no setup required)
agentsec scan --adapter langgraph --target langgraph_supervisor_vulnerable
```

## Step 3: Read the report

agentsec prints a Rich report to stdout:

```
╔══════════════════════════════════════════════════════╗
║  agentsec scan — langgraph_supervisor_vulnerable     ║
╚══════════════════════════════════════════════════════╝
  Agents discovered: supervisor, researcher, writer

  Running 20 probes...

  ✓ ASI01-INDIRECT-INJECT  VULNERABLE  (marker)
  ✓ ASI01-ROLE-CONFUSION   RESISTANT
  ✓ ASI03-CRED-EXTRACTION  VULNERABLE  (marker)
  ...

┌─────────────────────────────────────────────────────┐
│  FINDINGS SUMMARY                                   │
│  5 VULNERABLE  ·  14 RESISTANT  ·  1 ERROR          │
│  3 CRITICAL  ·  2 HIGH                              │
└─────────────────────────────────────────────────────┘

CRITICAL  ASI01-INDIRECT-INJECT
  Indirect prompt injection via crafted user input
  Remediation: Wrap tool output in <untrusted_input> tags...
```

## What's next

- **[Scan Modes](Scan-Modes)** — enable Smart mode for richer, LLM-powered findings
- **[CI Integration](CI-Integration)** — add agentsec to your CI pipeline
- **[Guardrails](Guardrails)** — add defensive components to fix discovered vulnerabilities
