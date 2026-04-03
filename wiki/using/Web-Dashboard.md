# Web Dashboard

The agentsec web dashboard provides a browser UI for running scans, browsing history, and managing findings.

## Start the dashboard

```bash
# Requires the dashboard extra
pip install "agentsec-framework[dashboard]"

agentsec serve
```

Opens at `http://127.0.0.1:8457` by default. Options:

```bash
agentsec serve --port 9000 --host 0.0.0.0 --no-open
```

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 8457 | Port to listen on |
| `--host` | 127.0.0.1 | Host to bind to |
| `--reload` | False | Auto-reload (development only) |
| `--open/--no-open` | `--open` | Open browser automatically |

---

## Panels

### Live scan progress

Start a scan from the UI by selecting a target and clicking **Run Scan**. The dashboard streams real-time probe status updates via SSE (Server-Sent Events). Each probe shows its ID, status (running / vulnerable / resistant / error), and detection method as it completes.

### Scan history

All completed scans are listed in the sidebar. Click any scan to load its full findings table. Compare scans over time to track whether remediations are working.

### Finding overrides

Mark findings as false positives or override their status with analyst notes:

1. Click a finding row in the findings table
2. Click **Override**
3. Select the new status and enter a justification (required)
4. Click **Save**

Overrides are recorded with the original status, new status, analyst ID, timestamp, and justification. The `compliance_flag: true` field on every override creates an audit trail.

### Export

Download results from any scan in three formats:

| Format | Use case |
|--------|----------|
| Markdown | Human-readable report for sharing |
| JSON | Machine-readable for downstream tooling |
| SARIF | Upload to GitHub/GitLab Security tab |

Click **Export** in the scan detail view and select the format.
