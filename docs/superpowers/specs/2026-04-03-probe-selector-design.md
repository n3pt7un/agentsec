# Probe Selector — Design Spec

**Date:** 2026-04-03
**Status:** Approved

## Problem

The dashboard's New Scan form has no way to filter which probes run. With 20 probes across 10 OWASP ASI categories, users need a way to target specific categories or individual probes without touching the CLI.

## Decisions

| Question | Decision |
|---|---|
| Selection model | Opt-out — all probes selected by default |
| Interaction model | Hierarchical tree: categories with expandable probe children |
| Form placement | Collapsible toggle row; collapsed by default |
| Backend encoding | Flat list of selected probe IDs (`probes: list[str]`) |

## UI Design

### Collapsed state (default)

A single row sits between the toggle checkboxes and the Submit button:

```
[ Probe selection                    20 / 20 probes ▾ ]
```

- Clicking anywhere on the row expands the panel
- The summary shows `N / 20 probes` and updates live as selections change
- When all 20 are selected the label color is the accent colour; when fewer are selected it shifts to a warning/muted tone

### Expanded state

A bordered panel opens below the toggle row with a fixed max-height (~260px) and `overflow-y: auto`.

```
[ select all ]  [ select none ]
─────────────────────────────────────────
☑  ASI01  Agent Goal Hijacking       2/2  ▾
   ☑  ASI01-INDIRECT-INJECT
   ☑  ASI01-ROLE-CONFUSION
─────────────────────────────────────────
☑  ASI02  Tool Misuse & Exploitation 2/2  ▾  (collapsed)
...
```

**Category rows** — always visible inside the panel:
- Checkbox: tri-state (checked / indeterminate / unchecked). Checking sets all children to checked; unchecking sets all children to unchecked.
- Clicking the row body (not the checkbox) toggles expand/collapse for that category's probe children.
- Shows `N/2` count of selected probes in that category.
- Expand arrow rotates on open/close.

**Probe rows** — visible only when their parent category is expanded:
- Individual checkboxes. Toggling one updates the parent category's tri-state.
- Probe ID displayed in monospace.

**Shortcuts row** at the top of the panel:
- "Select all" — checks every probe.
- "Select none" — unchecks every probe (Submit button disabled when 0 selected).

### Submit button

Disabled when 0 probes are selected (in addition to existing "no target" guard).

## Data Flow

### Frontend → API

`ScanForm` maintains a `Set<string>` of selected probe IDs in component state, initialised by fetching `/api/probes` on mount (the endpoint already exists and returns all probe metadata).

On submit, the `config` object gains a `probes` field:

```js
// All selected — send null (backend interprets as "run all")
probes: selectedProbes.size === totalProbes ? null : [...selectedProbes]
```

Sending `null` when everything is selected preserves the existing "run all" behaviour without enumerating all IDs unnecessarily.

### API → Backend

`ScanRequest` (in `routes/scans.py`) gains:

```python
probes: list[str] | None = None
```

`ScanManager.start_scan()` gains a matching `probes` parameter and passes it to `ScanConfig`:

```python
config = ScanConfig(
    categories=categories,
    probes=probes,        # new
    ...
)
```

`ScanConfig.probes` already exists and is already consumed by the `Scanner` — no changes needed beyond the gateway files.

## Files Changed

| File | Change |
|---|---|
| `src/agentsec/dashboard/routes/scans.py` | Add `probes: list[str] \| None = None` to `ScanRequest`; pass to `start_scan()` |
| `src/agentsec/dashboard/scan_manager.py` | Add `probes: list[str] \| None = None` param to `start_scan()`; pass to `ScanConfig` |
| `src/agentsec/dashboard/frontend/src/components/ScanForm.jsx` | Fetch probes on mount; add `probes` set to state; render collapsible tree; encode on submit |

No new files. No new API endpoints. No changes to `ScanConfig`, `Scanner`, or any probe code.

## Out of Scope

- Persisting the selection across page reloads (localStorage) — can be added later if needed.
- Search/filter within the probe list — 20 probes is manageable without it.
- Showing probe descriptions or severity badges in the tree — the tree is a selector, not a detail view.
