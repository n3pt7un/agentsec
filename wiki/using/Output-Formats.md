# Output Formats

agentsec supports three output formats. Specify with `--format` on `scan` or `report`.

## Markdown (default)

Human-readable report printed to stdout or written to a file.

```bash
agentsec scan --adapter langgraph --target ./my_agent.py
agentsec scan ... --format markdown --output report.md
```

Structure:
1. Scan header (target, timestamp, agents discovered)
2. Findings summary table (vulnerable count by severity)
3. One section per VULNERABLE finding with evidence and remediation code

## JSON

Machine-readable output with a metadata envelope.

```bash
agentsec scan ... --format json --output findings.json
```

Top-level structure:

```json
{
  "metadata": {
    "agentsec_version": "1.0.0b1",
    "generated_at": "2026-04-03T12:00:00Z"
  },
  "scan_result": {
    "target": "./my_agent.py",
    "started_at": "...",
    "finished_at": "...",
    "total_probes": 20,
    "vulnerable_count": 5,
    "resistant_count": 14,
    "error_count": 1,
    "findings": [
      {
        "probe_id": "ASI01-INDIRECT-INJECT",
        "probe_name": "Indirect Prompt Injection",
        "category": "ASI01",
        "status": "vulnerable",
        "severity": "critical",
        "description": "...",
        "evidence": {
          "attack_input": "...",
          "target_agent": "supervisor",
          "agent_response": "...",
          "detection_method": "marker"
        },
        "remediation": {
          "summary": "...",
          "code_before": "...",
          "code_after": "..."
        }
      }
    ]
  }
}
```

## SARIF 2.1.0

Standard format for CI/CD security findings. Consumed natively by GitHub, GitLab, and most CI tools.

```bash
agentsec scan ... --format sarif --output results.sarif
```

Severity mapping:

| agentsec severity | SARIF level |
|-------------------|-------------|
| critical | error |
| high | error |
| medium | warning |
| low | note |
| info | note |

Each VULNERABLE finding becomes a SARIF `result` with:
- `ruleId` = probe ID (e.g. `ASI01-INDIRECT-INJECT`)
- `message` = finding description + remediation summary
- `level` = mapped from severity

## Re-generating reports

Save findings as JSON once, re-generate any format:

```bash
# Save
agentsec scan ... --format json --output findings.json

# Re-generate as SARIF
agentsec report --input findings.json --format sarif --output results.sarif

# Re-generate as Markdown
agentsec report --input findings.json --format markdown
```

The `report` command reads either a raw `ScanResult` JSON or the metadata-wrapped JSON produced by `--format json`.
