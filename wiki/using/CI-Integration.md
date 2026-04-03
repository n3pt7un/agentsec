# CI Integration

agentsec outputs SARIF 2.1.0, the standard format for CI/CD security findings. Run offline mode in CI for speed; smart mode nightly for depth.

## GitHub Actions — SARIF upload to Security tab

```yaml
name: agentsec security scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  agentsec:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Install agentsec
        run: pip install agentsec-framework

      - name: Run agentsec scan
        run: |
          agentsec scan \
            --adapter langgraph \
            --target ./src/my_agent.py \
            --format sarif \
            --output results.sarif

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

Results appear in the **Security → Code scanning** tab on GitHub with severity badges and remediation details.

## GitHub Actions — fail on CRITICAL findings

```yaml
      - name: Run agentsec scan
        run: |
          agentsec scan \
            --adapter langgraph \
            --target ./src/my_agent.py \
            --format json \
            --output findings.json

      - name: Fail on CRITICAL findings
        run: |
          python - <<'EOF'
          import json, sys
          data = json.load(open("findings.json"))
          criticals = [
              f for f in data["scan_result"]["findings"]
              if f["status"] == "vulnerable" and f["severity"] == "critical"
          ]
          if criticals:
              for f in criticals:
                  print(f"CRITICAL: {f['probe_id']} — {f['description']}")
              sys.exit(1)
          EOF
```

## GitLab CI

```yaml
agentsec:
  stage: security
  image: python:3.12-slim
  script:
    - pip install agentsec-framework
    - agentsec scan --adapter langgraph --target ./src/my_agent.py --format sarif --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
    when: always
```

## Nightly smart scan

Run deeper LLM-powered analysis on a schedule:

```yaml
name: agentsec nightly smart scan

on:
  schedule:
    - cron: '0 2 * * *'   # 02:00 UTC every night

jobs:
  smart-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install "agentsec-framework[smart]"
      - name: Smart scan
        env:
          AGENTSEC_OPENROUTER_API_KEY: ${{ secrets.AGENTSEC_OPENROUTER_API_KEY }}
        run: |
          agentsec scan \
            --smart \
            --adapter langgraph \
            --target ./src/my_agent.py \
            --format sarif \
            --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed (findings may include VULNERABLE) |
| 1 | Error (bad args, auth failure, target load failure) |

agentsec does not exit 1 on VULNERABLE findings — use the JSON output + custom script pattern (see above) to implement a failure gate.
