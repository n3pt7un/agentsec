# Dashboard UI/UX Rework — Design Spec

**Date:** 2026-04-02  
**Scope:** Frontend only — `src/agentsec/dashboard/frontend/`. No backend changes.  
**Goal:** Modernize the dashboard with a deep-black dark mode inspired by Palantir data suites. Clean, structured, data-first aesthetic.

---

## Design Decisions Summary

| Dimension | Decision |
|---|---|
| Layout | Hybrid — slim 40px top bar + context panel on detail pages |
| Typography | IBM Plex Sans (UI text) + IBM Plex Mono (IDs, code, timestamps) |
| Accent color | Balanced green — logo, active nav, probe IDs, CTA borders, PASS indicators |
| Dark palette | `#060606` page · `#0d0d0d` cards · green-tinted borders |
| Light palette | Warm off-white · `#f7f6f3` page · `#efede8` cards · `#37352f` text |
| Icons | Tabler Icons — replaces all emoji throughout the UI |
| Border radius | Micro — 2px everywhere |
| Light mode | Kept, toggle fixed; dark is the primary/default mode |

---

## Implementation Strategy

Layer-by-layer, four sequential phases. Each phase is an independently reviewable unit. Phases 3 and 4 contain independent tasks suitable for subagent-driven parallel execution.

---

## Phase 1 — Design Tokens

### `src/agentsec/dashboard/frontend/src/tokens.css`

A single CSS file imported at the top of `index.css`. Both themes live here. The theme toggle switches `document.documentElement.dataset.theme` between `"dark"` (default) and `"light"`.

```css
/* Dark theme (default) */
[data-theme="dark"], :root {
  --bg-page:            #060606;
  --bg-surface:         #0d0d0d;
  --bg-surface-raised:  #111111;
  --border:             #1c1c1c;
  --border-green:       #1a2a1a;
  --border-red:         #2d1a1a;
  --text-primary:       #e2e8f0;
  --text-secondary:     #6b7280;
  --text-muted:         #374151;
  --accent:             #22c55e;
  --accent-dim:         #166534;
  --danger:             #f87171;
  --danger-bg:          #2d1a1a;
  --success-bg:         #0a1f0a;
  --font-sans:          'IBM Plex Sans', sans-serif;
  --font-mono:          'IBM Plex Mono', monospace;
  --radius:             2px;
}

/* Light theme */
[data-theme="light"] {
  --bg-page:            #f7f6f3;
  --bg-surface:         #efede8;
  --bg-surface-raised:  #e8e6e0;
  --border:             #dbd8d0;
  --border-green:       #c0d8c0;
  --border-red:         #e8c4c4;
  --text-primary:       #37352f;
  --text-secondary:     #9a9488;
  --text-muted:         #b0a89e;
  --accent:             #15803d;
  --accent-dim:         #166534;
  --danger:             #b91c1c;
  --danger-bg:          #fdf2f2;
  --success-bg:         #f0f7f0;
}
```

### `src/agentsec/dashboard/frontend/src/hooks/useTheme.js`

Rewrite to use `data-theme` attribute instead of the broken `.dark` class toggle. Initialize from `localStorage`, fall back to `"dark"`.

```js
// sets document.documentElement.dataset.theme = 'dark' | 'light'
// persists to localStorage('agentsec-theme')
```

### `index.css`

- Import `tokens.css` first
- Import IBM Plex Sans and IBM Plex Mono from Google Fonts
- Remove all slate-color scrollbar overrides; replace with token-based equivalents
- Set `body { font-family: var(--font-sans); background: var(--bg-page); color: var(--text-primary); }`

---

## Phase 2 — Layout & Navigation

### `src/agentsec/dashboard/frontend/src/components/Layout.jsx`

Full rewrite. Key changes:

**Top bar (40px):**
- Left: `AGENTSEC` wordmark — IBM Plex Mono, `var(--accent)`, `letter-spacing: 0.1em`, 11px, no emoji
- Center: nav links — IBM Plex Sans 13px. Active: `color: var(--accent)`, `border-bottom: 1px solid var(--accent)`. Inactive: `color: var(--text-muted)`. Hover: `color: var(--text-secondary)`
- Right: theme toggle — Tabler `IconSun` (16px) in light mode, `IconMoon` in dark mode. `color: var(--text-muted)`, hover `var(--text-primary)`. No text label.
- Bar background: `var(--bg-surface)`, bottom border: `1px solid var(--border-green)`

**Context panel (detail pages only):**
- Rendered as a sticky `<aside>` (160px wide) when `location.pathname` matches `/scans/:id` or `/scans/:id/progress`
- Contains jump links to page sections: Stats, Agent Graph, Findings (or Progress, Summary during scan)
- Active section tracked via `IntersectionObserver` on each section's anchor `<div>` — the jump link for the most recently intersected section gets `color: var(--accent)`
- Font: IBM Plex Sans 11px, `var(--text-muted)`. Active section: `var(--accent)`
- Background: `var(--bg-surface)`, right border: `1px solid var(--border)`
- The `<main>` wrapper becomes a flex row: `aside` + `<div className="content">` when panel is active

**Remove:** light/dark mode emoji (☀️🌙), emoji nav icons (⚡📋⚙️🛡️)

### Tabler Icons installation

```
npm install @tabler/icons-react
```

Nav icon mapping:
- Dashboard → `IconLayoutDashboard`
- Scan History → `IconClipboardList`
- Settings → `IconSettings`
- Theme toggle → `IconSun` / `IconMoon`

All icons: `size={16}`, `stroke={1.25}`, `color="currentColor"`

---

## Phase 3 — Component Restyle

All components drop hardcoded Tailwind color classes and reference CSS variables. No Tailwind `dark:` prefixes — theming is handled entirely by token overrides.

### `SeverityBadge.jsx` / `StatusBadge.jsx`

- Font: IBM Plex Mono, 10px, uppercase, `letter-spacing: 0.06em`
- VULN badge: `IconAlertTriangle` (12px) prefix, `color: var(--danger)`, `background: var(--danger-bg)`, `border: 1px solid var(--border-red)`
- PASS badge: `IconShieldCheck` (12px) prefix, `color: var(--accent)`, `background: var(--success-bg)`, `border: 1px solid var(--border-green)`
- ERROR badge: `IconX` prefix, `color: var(--danger)`, `background: var(--danger-bg)`, `border: 1px solid var(--border-red)`, `opacity: 0.7`

### `FindingCard.jsx`

- Surface: `background: var(--bg-surface)`, `border: 1px solid var(--border)`
- VULN findings: `border-left: 2px solid var(--danger)`
- PASS findings: `border-left: 2px solid var(--accent-dim)`
- Probe ID: IBM Plex Mono, `color: var(--accent)`, 12px
- Probe name: IBM Plex Sans, `color: var(--text-secondary)`, 13px
- Expand/collapse: Tabler `IconChevronDown` / `IconChevronUp` replacing `▼▲`
- Duration: IBM Plex Mono, `color: var(--text-muted)`, 11px

### `CodeBlock.jsx`

- Outer wrapper: `background: var(--bg-page)`, `border: 1px solid var(--border)`, `border-radius: var(--radius)`, `padding: 12px`
- Font: IBM Plex Mono 12px, `color: var(--text-primary)`
- Copy button: Tabler `IconCopy` → `IconCheck` (with 1.5s reset). `color: var(--text-muted)`, hover `var(--accent)`

### `ScanCard.jsx`

- Status indicator: 6px dot — scanning: pulsing `var(--accent)`, complete: solid `var(--accent)`, error: `var(--danger)`
- Target path: IBM Plex Mono, `color: var(--text-primary)`, 13px
- Metadata (timestamp, probe count): IBM Plex Sans, `color: var(--text-muted)`, 12px
- Card: `background: var(--bg-surface)`, `border: 1px solid var(--border)`, hover: `border-color: var(--border-green)`

### `ProbeProgress.jsx`

- Each probe row: icon prefix
  - Running: Tabler `IconRadar` with CSS spin animation, `color: var(--accent)`
  - Pass: `IconCheck`, `color: var(--accent)`
  - Fail/error: `IconX`, `color: var(--danger)`
- Progress bar: `background: var(--bg-surface-raised)` track, `var(--accent)` fill
- Probe ID: IBM Plex Mono, `color: var(--accent)`

### `AgentGraph.jsx` (D3)

- Node: `fill: var(--bg-surface-raised)`, `stroke: var(--border-green)`, `stroke-width: 1`
- Selected node: `stroke: var(--accent)`, `stroke-width: 1.5`
- Edge: `stroke: var(--accent-dim)`, `stroke-width: 1`, `opacity: 0.6`
- Label: IBM Plex Mono 10px, `fill: var(--text-secondary)`
- Read CSS variable values via `getComputedStyle(document.documentElement)` so D3 respects the active theme

### `ScanForm.jsx`

- Inputs: `background: var(--bg-surface)`, `border: 1px solid var(--border)`, focus: `border-color: var(--accent)`, `outline: none`
- Font: IBM Plex Sans 13px, `color: var(--text-primary)`
- Placeholder: `color: var(--text-muted)`
- Submit button: ghost style — `border: 1px solid var(--accent)`, `color: var(--accent)`, `background: transparent`, hover: `background: var(--success-bg)`

### `FindingFilters.jsx`

- Filter pills: `border: 1px solid var(--border)`, `color: var(--text-secondary)`, `border-radius: var(--radius)`
- Active pill: `border-color: var(--accent)`, `color: var(--accent)`, `background: var(--success-bg)`

### `SummaryTable.jsx`

- Header row: IBM Plex Sans 11px, uppercase, `letter-spacing: 0.08em`, `color: var(--text-muted)`
- Even rows: `background: var(--bg-surface)`
- Odd rows: `background: var(--bg-surface-raised)`
- Borders: `1px solid var(--border)`

### `EmptyState.jsx`

- Replace emoji with Tabler `IconInbox` (32px), `color: var(--text-muted)`
- Text: IBM Plex Sans, `color: var(--text-secondary)`

### `ErrorState.jsx`

- Replace emoji with Tabler `IconAlertCircle` (32px), `color: var(--danger)`

### `LoadingSkeleton.jsx`

- Skeleton blocks: `background: var(--bg-surface-raised)`, CSS pulse animation
- Remove hardcoded `bg-slate-800` / `bg-slate-700` classes

---

## Phase 4 — Page-level Layouts

### `pages/Dashboard.jsx`

- Stat cards: 4-col grid, `background: var(--bg-surface)`, `border: 1px solid var(--border)`
- Stat numbers: IBM Plex Mono, 24px. Vuln count: `color: var(--danger)`. Pass count: `color: var(--accent)`
- Stat labels: IBM Plex Sans 11px uppercase, `color: var(--text-muted)`, `letter-spacing: 0.08em`
- ScanForm card sits above scan history, full width

### `pages/ScanProgress.jsx`

- Header: IBM Plex Sans 16px, `font-weight: 600`
- "View Results" button: same ghost style as ScanForm submit
- Completion summary: same 4-col stat grid as ScanDetail

### `pages/ScanDetail.jsx`

- Section headings: IBM Plex Sans 13px uppercase, `letter-spacing: 0.08em`, `color: var(--text-muted)`, with `id` anchors matching the context panel jump links
- Delete button: moves from the header into a `IconDots` context menu (Tabler) to reduce visual noise. Options: "Delete scan" in `color: var(--danger)`
- Findings count label: IBM Plex Mono, `color: var(--text-muted)`, 12px

### `pages/ScanHistory.jsx`

- Page title: IBM Plex Sans 16px, `font-weight: 600`
- Empty state uses the new `EmptyState` component

### `pages/Settings.jsx`

- Section labels: IBM Plex Sans 11px uppercase, `color: var(--text-muted)`
- API key input: IBM Plex Mono (secrets look right in monospace)
- Model picker `<select>`: styled with token borders and background

---

## Files Changed

**New:**
- `src/tokens.css`

**Modified:**
- `src/index.css` — import tokens, Google Fonts, remove slate overrides
- `src/hooks/useTheme.js` — rewrite to `data-theme` attribute approach
- `src/components/Layout.jsx` — hybrid nav, Tabler icons, fixed toggle
- `src/components/SeverityBadge.jsx`
- `src/components/FindingCard.jsx`
- `src/components/CodeBlock.jsx`
- `src/components/ScanCard.jsx`
- `src/components/ProbeProgress.jsx`
- `src/components/AgentGraph.jsx`
- `src/components/ScanForm.jsx`
- `src/components/FindingFilters.jsx`
- `src/components/SummaryTable.jsx`
- `src/components/EmptyState.jsx`
- `src/components/ErrorState.jsx`
- `src/components/LoadingSkeleton.jsx`
- `src/pages/Dashboard.jsx`
- `src/pages/ScanProgress.jsx`
- `src/pages/ScanDetail.jsx`
- `src/pages/ScanHistory.jsx`
- `src/pages/Settings.jsx`
- `package.json` — add `@tabler/icons-react`

**Not changed:** all backend Python files, API routes, SSE stream, scan logic, data models.

---

## Constraints

- No backend changes whatsoever
- No new pages or routes
- No new data fetching — all components retain their existing props/data interfaces
- `@tabler/icons-react` is the only new npm dependency
- Google Fonts loaded via `@import` in CSS (no new npm font packages)
- All D3 color values read from CSS variables at render time, not hardcoded
