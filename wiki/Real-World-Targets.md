# Real-World Targets

agentsec ships adapter harnesses for six open-source LangGraph multi-agent projects. Use them to run agentsec against realistic systems in CI without any external API calls.

## Install

```bash
pip install "agentsec-framework[targets]"
# or
uv sync --extra targets
```

## Available targets

### langgraph_supervisor_vulnerable

**Architecture:** Supervisor + worker agents with handoff tools.
**Key attack surfaces:** Supervisor trust, tool delegation, handoff manipulation.

```bash
agentsec scan --adapter langgraph --target langgraph_supervisor_vulnerable
```

Expected critical findings: ASI01-INDIRECT-INJECT, ASI03-CRED-EXTRACTION, ASI07-ORCHESTRATOR-HIJACK.

---

### langgraph_swarm_vulnerable

**Architecture:** Swarm with dynamic agent handoffs and shared memory.
**Key attack surfaces:** Agent identity in handoffs, shared memory across agents.

```bash
agentsec scan --adapter langgraph --target langgraph_swarm_vulnerable
```

Expected critical findings: ASI01-INDIRECT-INJECT, ASI06-MEMORY-POISON, ASI07-ORCHESTRATOR-HIJACK.

---

### multi_agent_rag_customer_support_vulnerable

**Architecture:** Travel booking RAG with safe/sensitive tool separation.
**Key attack surfaces:** RAG poisoning, tool privilege separation, cross-assistant data leaks.

```bash
agentsec scan --adapter langgraph --target multi_agent_rag_customer_support_vulnerable
```

Expected critical findings: ASI01-INDIRECT-INJECT, ASI04-TOOL-POISONING.

---

### langgraph_email_automation_vulnerable

**Architecture:** Email categorization pipeline with RAG response drafting.
**Key attack surfaces:** Email content injection, RAG context manipulation.

```bash
agentsec scan --adapter langgraph --target langgraph_email_automation_vulnerable
```

Expected critical findings: ASI01-INDIRECT-INJECT, ASI05-CODE-INJECTION.

---

### rag_research_agent_vulnerable

**Architecture:** Research RAG with a researcher subgraph.
**Key attack surfaces:** Subgraph isolation, retriever manipulation, memory scoping.

```bash
agentsec scan --adapter langgraph --target rag_research_agent_vulnerable
```

Expected critical findings: ASI04-DEPENDENCY-INJECT, ASI06-MEMORY-POISON.

---

### multi_agentic_rag_vulnerable

**Architecture:** RAG with hallucination checks and error correction loops.
**Key attack surfaces:** Bypassing hallucination guards, error correction exploitation.

```bash
agentsec scan --adapter langgraph --target multi_agentic_rag_vulnerable
```

Expected critical findings: ASI08-CASCADE-TRIGGER, ASI10-OBJECTIVE-DIVERGE.

---

## Harness variants

Each target ships in two variants:

| Variant | Flag | Description |
|---------|------|-------------|
| Vulnerable | `--vulnerable` (default) | Misconfigured to expose vulnerabilities |
| Hardened | `--no-vulnerable` | Patched with the recommended remediations |

```bash
# Compare vulnerable vs hardened
agentsec scan --adapter langgraph --target langgraph_supervisor_vulnerable
agentsec scan --adapter langgraph --target langgraph_supervisor_vulnerable --no-vulnerable
```

The hardened variant should produce zero VULNERABLE findings for all probes that the harness covers.
