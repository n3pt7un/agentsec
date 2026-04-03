# Probe Selector

Run all 20 probes, or select a specific subset by ID, category, or severity.

## Run a single probe

```bash
agentsec probe ASI01-INDIRECT-INJECT --adapter langgraph --target ./my_agent.py
```

The `probe` command runs one probe and prints its full finding detail, including attack payload, agent response, and remediation.

## Filter by probe ID (scan command)

```bash
agentsec scan --probes ASI01-INDIRECT-INJECT,ASI03-CRED-EXTRACTION \
  --adapter langgraph --target ./my_agent.py
```

`--probes` accepts a comma-separated list of probe IDs. Only those probes run.

## Filter by OWASP category

```bash
agentsec scan --categories ASI01,ASI03 \
  --adapter langgraph --target ./my_agent.py
```

`--categories` accepts a comma-separated list of `ASI01`–`ASI10`. Runs all probes for those categories.

## List all probes

```bash
agentsec probes list
```

Output:

```
 Probe ID                    Category  Severity   Name
 ─────────────────────────────────────────────────────────────────────
 ASI01-INDIRECT-INJECT       ASI01     CRITICAL   Indirect Prompt Injection
 ASI01-ROLE-CONFUSION        ASI01     HIGH       Role Confusion
 ASI02-PARAM-INJECTION       ASI02     HIGH       Parameter Injection
 ...
```

Filter by category:

```bash
agentsec probes list --category ASI01
```

## Probe ID naming convention

All probe IDs follow the pattern `ASI<NN>-<SLUG>`:

- `ASI<NN>` — OWASP Agentic category number (01–10)
- `<SLUG>` — Short uppercase slug describing the attack type

Examples: `ASI01-INDIRECT-INJECT`, `ASI07-ORCHESTRATOR-HIJACK`, `ASI10-COVERT-EXFIL`

See the full list: **[Probe Index](Probe-Index)**
