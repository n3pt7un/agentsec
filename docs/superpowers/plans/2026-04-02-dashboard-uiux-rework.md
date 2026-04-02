# Dashboard UI/UX Rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restyle the React dashboard with deep-black dark mode, IBM Plex fonts, Tabler icons, balanced terminal-green accents, 2px radius, and a hybrid nav — frontend only, no backend changes.

**Architecture:** CSS custom properties (`tokens.css`) drive both dark and light themes via `[data-theme]` on `<html>`. Layout adds a slim top bar and opt-in `ContextPanel` for detail pages. Components replace hardcoded Tailwind color classes with inline `style` referencing tokens. Tailwind v4 remains for layout utilities (flex, grid, spacing) only.

**Tech Stack:** React 19, Tailwind CSS v4, Vite 8, `@tabler/icons-react`, IBM Plex fonts (Google Fonts CDN), D3 v7, highlight.js

---

## Execution Order

```
Task 1  →  Task 2  →  [Tasks 3–7 in parallel]  →  [Tasks 8–12 in parallel]
```

Tasks 3–7 are **PARALLEL BATCH A** — dispatch simultaneously after Task 2 is committed.
Tasks 8–12 are **PARALLEL BATCH B** — dispatch simultaneously after all of Batch A is committed.

---

## Task 1: Design Tokens + Theme System

**Files:**
- Create: `src/agentsec/dashboard/frontend/src/tokens.css`
- Modify: `src/agentsec/dashboard/frontend/src/hooks/useTheme.js`
- Modify: `src/agentsec/dashboard/frontend/src/index.css`

- [ ] **Step 1: Create `tokens.css`**

```css
/* src/agentsec/dashboard/frontend/src/tokens.css */

/* Dark theme — default */
[data-theme="dark"],
:root {
  --bg-page:           #060606;
  --bg-surface:        #0d0d0d;
  --bg-surface-raised: #111111;
  --border:            #1c1c1c;
  --border-green:      #1a2a1a;
  --border-red:        #2d1a1a;
  --text-primary:      #e2e8f0;
  --text-secondary:    #6b7280;
  --text-muted:        #374151;
  --accent:            #22c55e;
  --accent-dim:        #166534;
  --danger:            #f87171;
  --danger-bg:         #2d1a1a;
  --success-bg:        #0a1f0a;
  --warning:           #fbbf24;
  --warning-bg:        #2d2200;
  --font-sans:         'IBM Plex Sans', sans-serif;
  --font-mono:         'IBM Plex Mono', monospace;
  --radius:            2px;
}

/* Light theme */
[data-theme="light"] {
  --bg-page:           #f7f6f3;
  --bg-surface:        #efede8;
  --bg-surface-raised: #e8e6e0;
  --border:            #dbd8d0;
  --border-green:      #c0d8c0;
  --border-red:        #e8c4c4;
  --text-primary:      #37352f;
  --text-secondary:    #9a9488;
  --text-muted:        #b0a89e;
  --accent:            #15803d;
  --accent-dim:        #166534;
  --danger:            #b91c1c;
  --danger-bg:         #fdf2f2;
  --success-bg:        #f0f7f0;
  --warning:           #92400e;
  --warning-bg:        #fffbeb;
}
```

- [ ] **Step 2: Rewrite `useTheme.js`**

The current implementation sets a `.dark` class which Tailwind v4 doesn't wire correctly for CSS variable overrides. Rewrite to use `data-theme` attribute.

```js
// src/agentsec/dashboard/frontend/src/hooks/useTheme.js
import { useState, useEffect } from 'react';

export function useTheme() {
  const [theme, setTheme] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('agentsec-theme') || 'dark';
    }
    return 'dark';
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('agentsec-theme', theme);
  }, [theme]);

  const toggle = () => setTheme(t => t === 'dark' ? 'light' : 'dark');

  return { theme, toggle };
}
```

- [ ] **Step 3: Rewrite `index.css`**

```css
/* src/agentsec/dashboard/frontend/src/index.css */
@import "tailwindcss";
@import "./tokens.css";
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

body {
  font-family: var(--font-sans);
  background: var(--bg-page);
  color: var(--text-primary);
}

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-surface); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

/* highlight.js: always dark regardless of theme */
pre code.hljs { background: #0d1117 !important; }
```

- [ ] **Step 4: Verify build succeeds**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: build completes with no errors. Google Fonts will load at runtime, not build time — ignore any "external resource" notes.

- [ ] **Step 5: Commit**

```bash
git add src/agentsec/dashboard/frontend/src/tokens.css \
        src/agentsec/dashboard/frontend/src/hooks/useTheme.js \
        src/agentsec/dashboard/frontend/src/index.css
git commit -m "FEAT: add CSS design tokens and fix theme toggle to use data-theme attribute"
```

---

## Task 2: Install Tabler + Layout + ContextPanel

**Files:**
- Modify: `src/agentsec/dashboard/frontend/package.json` (via npm install)
- Create: `src/agentsec/dashboard/frontend/src/hooks/useActiveSection.js`
- Create: `src/agentsec/dashboard/frontend/src/components/ContextPanel.jsx`
- Modify: `src/agentsec/dashboard/frontend/src/components/Layout.jsx`

- [ ] **Step 1: Install Tabler Icons**

```bash
cd src/agentsec/dashboard/frontend && npm install @tabler/icons-react
```

Expected: `@tabler/icons-react` appears in `package.json` dependencies and `node_modules`.

- [ ] **Step 2: Create `useActiveSection.js`**

Used by `ContextPanel` to highlight the current in-view section.

```js
// src/agentsec/dashboard/frontend/src/hooks/useActiveSection.js
import { useState, useEffect } from 'react';

export function useActiveSection(sectionIds) {
  const [activeId, setActiveId] = useState(sectionIds[0] ?? null);

  useEffect(() => {
    if (sectionIds.length === 0) return;

    const observers = sectionIds.map(id => {
      const el = document.getElementById(id);
      if (!el) return null;
      const obs = new IntersectionObserver(
        ([entry]) => { if (entry.isIntersecting) setActiveId(id); },
        { threshold: 0.2, rootMargin: '-10% 0px -70% 0px' }
      );
      obs.observe(el);
      return obs;
    });

    return () => observers.forEach(o => o?.disconnect());
  }, [sectionIds.join(',')]); // eslint-disable-line react-hooks/exhaustive-deps

  return activeId;
}
```

- [ ] **Step 3: Create `ContextPanel.jsx`**

Opt-in sidebar for detail pages. Pages that want it wrap their content in a flex row and include `<ContextPanel sections={[...]} />`.

```jsx
// src/agentsec/dashboard/frontend/src/components/ContextPanel.jsx
import { useActiveSection } from '../hooks/useActiveSection';

export default function ContextPanel({ sections }) {
  const ids = sections.map(s => s.id);
  const activeId = useActiveSection(ids);

  return (
    <aside style={{
      width: '148px',
      flexShrink: 0,
      position: 'sticky',
      top: '56px',
      alignSelf: 'flex-start',
      paddingRight: '16px',
      borderRight: '1px solid var(--border)',
    }}>
      <nav style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
        {sections.map(s => (
          <a
            key={s.id}
            href={`#${s.id}`}
            style={{
              display: 'block',
              padding: '5px 0',
              fontSize: '11px',
              fontFamily: 'var(--font-sans)',
              color: activeId === s.id ? 'var(--accent)' : 'var(--text-muted)',
              textDecoration: 'none',
              letterSpacing: '0.02em',
              transition: 'color 0.1s',
            }}
          >
            {s.label}
          </a>
        ))}
      </nav>
    </aside>
  );
}
```

- [ ] **Step 4: Rewrite `Layout.jsx`**

Slim 40px top bar: `AGENTSEC` wordmark left, nav center, theme toggle right. No emojis.

```jsx
// src/agentsec/dashboard/frontend/src/components/Layout.jsx
import { Link, Outlet, useLocation } from 'react-router-dom';
import { useTheme } from '../hooks/useTheme';
import {
  IconLayoutDashboard,
  IconClipboardList,
  IconSettings,
  IconSun,
  IconMoon,
} from '@tabler/icons-react';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: IconLayoutDashboard },
  { to: '/scans', label: 'Scan History', icon: IconClipboardList },
  { to: '/settings', label: 'Settings', icon: IconSettings },
];

export default function Layout() {
  const location = useLocation();
  const { theme, toggle } = useTheme();

  const isActive = (to) =>
    to === '/' ? location.pathname === '/' : location.pathname.startsWith(to);

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-page)', color: 'var(--text-primary)' }}>
      {/* Top bar */}
      <nav style={{
        height: '40px',
        background: 'var(--bg-surface)',
        borderBottom: '1px solid var(--border-green)',
        display: 'flex',
        alignItems: 'center',
        padding: '0 24px',
        gap: '32px',
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}>
        {/* Wordmark */}
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
          fontWeight: 600,
          color: 'var(--accent)',
          letterSpacing: '0.12em',
          userSelect: 'none',
        }}>
          AGENTSEC
        </span>

        {/* Nav links */}
        <div style={{ display: 'flex', gap: '4px' }}>
          {NAV_ITEMS.map(({ to, label, icon: Icon }) => {
            const active = isActive(to);
            return (
              <Link
                key={to}
                to={to}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '4px 10px',
                  fontSize: '13px',
                  fontFamily: 'var(--font-sans)',
                  color: active ? 'var(--accent)' : 'var(--text-muted)',
                  textDecoration: 'none',
                  borderBottom: active ? '1px solid var(--accent)' : '1px solid transparent',
                  transition: 'color 0.1s',
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.color = 'var(--text-secondary)'; }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.color = 'var(--text-muted)'; }}
              >
                <Icon size={14} stroke={1.25} />
                {label}
              </Link>
            );
          })}
        </div>

        {/* Theme toggle */}
        <button
          onClick={toggle}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          style={{
            marginLeft: 'auto',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            padding: '4px',
            borderRadius: 'var(--radius)',
            transition: 'color 0.1s',
          }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--text-primary)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; }}
        >
          {theme === 'dark'
            ? <IconSun size={16} stroke={1.25} />
            : <IconMoon size={16} stroke={1.25} />}
        </button>
      </nav>

      {/* Page content */}
      <main style={{ maxWidth: '1280px', margin: '0 auto', padding: '32px 24px' }}>
        <Outlet />
      </main>
    </div>
  );
}
```

- [ ] **Step 5: Verify build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: no errors. The layout should compile cleanly with the new Tabler imports.

- [ ] **Step 6: Commit**

```bash
git add src/agentsec/dashboard/frontend/package.json \
        src/agentsec/dashboard/frontend/package-lock.json \
        src/agentsec/dashboard/frontend/src/hooks/useActiveSection.js \
        src/agentsec/dashboard/frontend/src/components/ContextPanel.jsx \
        src/agentsec/dashboard/frontend/src/components/Layout.jsx
git commit -m "FEAT: install Tabler icons, redesign top bar, add ContextPanel with IntersectionObserver"
```

---

## ⚡ PARALLEL BATCH A — Tasks 3–7

> Dispatch all five tasks simultaneously. Each task is fully independent. They all operate on different files and only depend on the tokens and imports established in Tasks 1–2.

---

## Task 3: SeverityBadge + FindingCard + FindingDetail

**Files:**
- Modify: `src/agentsec/dashboard/frontend/src/components/SeverityBadge.jsx`
- Modify: `src/agentsec/dashboard/frontend/src/components/FindingCard.jsx`
- Modify: `src/agentsec/dashboard/frontend/src/components/FindingDetail.jsx`

- [ ] **Step 1: Rewrite `SeverityBadge.jsx`**

Replaces hardcoded Tailwind color classes with token-based inline styles. Adds Tabler icon prefixes to StatusBadge entries.

```jsx
// src/agentsec/dashboard/frontend/src/components/SeverityBadge.jsx
import {
  IconAlertTriangle,
  IconShieldCheck,
  IconAdjustments,
  IconX,
  IconPlayerSkipForward,
  IconAlertCircle,
} from '@tabler/icons-react';

const SEVERITY_STYLES = {
  critical: { color: '#f87171', bg: '#3d1515', border: '#7f1d1d' },
  high:     { color: '#fb923c', bg: '#2d1a0a', border: '#7c2d12' },
  medium:   { color: '#fbbf24', bg: '#2d2200', border: '#78350f' },
  low:      { color: '#60a5fa', bg: '#0a1a2d', border: '#1e3a5f' },
  info:     { color: 'var(--text-secondary)', bg: 'var(--bg-surface-raised)', border: 'var(--border)' },
};

const STATUS_CONFIG = {
  vulnerable: { color: 'var(--danger)', bg: 'var(--danger-bg)', border: 'var(--border-red)', Icon: IconAlertTriangle },
  resistant:  { color: 'var(--accent)', bg: 'var(--success-bg)', border: 'var(--border-green)', Icon: IconShieldCheck },
  partial:    { color: '#fbbf24', bg: '#2d2200', border: '#78350f', Icon: IconAdjustments },
  error:      { color: 'var(--danger)', bg: 'var(--danger-bg)', border: 'var(--border-red)', Icon: IconX },
  skipped:    { color: 'var(--text-muted)', bg: 'var(--bg-surface-raised)', border: 'var(--border)', Icon: IconPlayerSkipForward },
};

export function SeverityBadge({ severity }) {
  const s = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info;
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      padding: '1px 6px',
      borderRadius: 'var(--radius)',
      border: `1px solid ${s.border}`,
      background: s.bg,
      color: s.color,
      fontSize: '10px',
      fontFamily: 'var(--font-mono)',
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: '0.06em',
    }}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }) {
  const s = STATUS_CONFIG[status] ?? STATUS_CONFIG.skipped;
  const { Icon } = s;
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '3px',
      padding: '1px 6px',
      borderRadius: 'var(--radius)',
      border: `1px solid ${s.border}`,
      background: s.bg,
      color: s.color,
      fontSize: '10px',
      fontFamily: 'var(--font-mono)',
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: '0.06em',
    }}>
      <Icon size={10} stroke={2} />
      {status}
    </span>
  );
}
```

- [ ] **Step 2: Rewrite `FindingCard.jsx`**

Left border accent signals status at a glance. Tabler chevron replaces text arrows.

```jsx
// src/agentsec/dashboard/frontend/src/components/FindingCard.jsx
import { useState } from 'react';
import { IconChevronDown, IconChevronUp } from '@tabler/icons-react';
import { SeverityBadge, StatusBadge } from './SeverityBadge';
import FindingDetail from './FindingDetail';

const LEFT_BORDER = {
  vulnerable: 'var(--danger)',
  resistant:  'var(--accent-dim)',
  partial:    '#78350f',
  error:      'var(--danger)',
  skipped:    'var(--border)',
};

export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const accentColor = LEFT_BORDER[finding.status] ?? 'var(--border)';

  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderLeft: `2px solid ${accentColor}`,
      borderRadius: 'var(--radius)',
      overflow: 'hidden',
    }}>
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          width: '100%',
          padding: '10px 14px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
          transition: 'background 0.1s',
        }}
        onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-surface-raised)'; }}
        onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <StatusBadge status={finding.status} />
          <SeverityBadge severity={finding.severity} />
          <div>
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              color: 'var(--accent)',
            }}>
              {finding.probe_id}
            </span>
            <span style={{
              fontSize: '12px',
              color: 'var(--text-secondary)',
              marginLeft: '8px',
              fontFamily: 'var(--font-sans)',
            }}>
              {finding.probe_name}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {finding.duration_ms != null && (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
              {finding.duration_ms}ms
            </span>
          )}
          <span style={{ color: 'var(--text-muted)' }}>
            {expanded
              ? <IconChevronUp size={14} stroke={1.5} />
              : <IconChevronDown size={14} stroke={1.5} />}
          </span>
        </div>
      </button>

      {expanded && (
        <div style={{ padding: '0 14px 14px' }}>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '8px', fontFamily: 'var(--font-sans)' }}>
            {finding.description}
          </p>
          <FindingDetail finding={finding} />
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Rewrite `FindingDetail.jsx`**

Replaces hardcoded Tailwind colors with token-based inline styles.

```jsx
// src/agentsec/dashboard/frontend/src/components/FindingDetail.jsx
import CodeBlock from './CodeBlock';

export default function FindingDetail({ finding }) {
  const { evidence, remediation } = finding;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px', borderTop: '1px solid var(--border)' }}>
      {/* Evidence */}
      {evidence && (
        <div>
          <h4 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', fontFamily: 'var(--font-sans)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Evidence
          </h4>
          <div style={{
            background: 'var(--bg-page)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            padding: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            fontSize: '12px',
          }}>
            <div>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Attack input: </span>
              <code style={{ color: 'var(--danger)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{evidence.attack_input}</code>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Target agent: </span>
              <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>{evidence.target_agent}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Response: </span>
              <code style={{ color: '#fb923c', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{evidence.agent_response}</code>
            </div>
            {evidence.additional_context && (
              <div>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Context: </span>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-sans)' }}>{evidence.additional_context}</span>
              </div>
            )}
            {evidence.detection_method && (
              <div>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Detection: </span>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-sans)' }}>{evidence.detection_method}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Blast radius */}
      {finding.blast_radius && (
        <div style={{
          background: 'var(--danger-bg)',
          border: '1px solid var(--border-red)',
          borderRadius: 'var(--radius)',
          padding: '10px 12px',
          fontSize: '12px',
          color: 'var(--danger)',
          fontFamily: 'var(--font-sans)',
        }}>
          <span style={{ fontWeight: 600 }}>Blast radius: </span>
          {finding.blast_radius}
        </div>
      )}

      {/* Remediation */}
      {remediation && (
        <div>
          <h4 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', fontFamily: 'var(--font-sans)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Remediation
          </h4>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '12px', fontFamily: 'var(--font-sans)' }}>
            {remediation.summary}
          </p>
          {remediation.code_before && (
            <CodeBlock code={remediation.code_before} label="Before (vulnerable):" />
          )}
          {remediation.code_after && (
            <CodeBlock code={remediation.code_after} label="After (fixed):" />
          )}
          {remediation.architecture_note && (
            <div style={{
              borderLeft: '2px solid var(--accent-dim)',
              paddingLeft: '12px',
              paddingTop: '8px',
              paddingBottom: '8px',
              fontSize: '12px',
              color: 'var(--text-secondary)',
              marginTop: '12px',
              fontFamily: 'var(--font-sans)',
            }}>
              {remediation.architecture_note}
            </div>
          )}
          {remediation.references?.length > 0 && (
            <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {remediation.references.map((ref, i) => (
                <a key={i} href={ref} target="_blank" rel="noopener"
                   style={{ fontSize: '11px', color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
                  {ref}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Verify build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add src/agentsec/dashboard/frontend/src/components/SeverityBadge.jsx \
        src/agentsec/dashboard/frontend/src/components/FindingCard.jsx \
        src/agentsec/dashboard/frontend/src/components/FindingDetail.jsx
git commit -m "FEAT: restyle SeverityBadge, FindingCard, FindingDetail with tokens and Tabler icons"
```

---

## Task 4: CodeBlock + ScanCard

**Files:**
- Modify: `src/agentsec/dashboard/frontend/src/components/CodeBlock.jsx`
- Modify: `src/agentsec/dashboard/frontend/src/components/ScanCard.jsx`

- [ ] **Step 1: Rewrite `CodeBlock.jsx`**

Adds copy-to-clipboard with Tabler icons. Wrapper uses token-based styles. Code blocks stay dark in both themes (handled by `index.css` override from Task 1).

```jsx
// src/agentsec/dashboard/frontend/src/components/CodeBlock.jsx
import { useEffect, useRef, useState } from 'react';
import { IconCopy, IconCheck } from '@tabler/icons-react';
import hljs from 'highlight.js/lib/core';
import python from 'highlight.js/lib/languages/python';
import 'highlight.js/styles/github-dark.css';

hljs.registerLanguage('python', python);

export default function CodeBlock({ code, language = 'python', label }) {
  const codeRef = useRef(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (codeRef.current) {
      delete codeRef.current.dataset.highlighted;
      hljs.highlightElement(codeRef.current);
    }
  }, [code]);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  if (!code) return null;

  return (
    <div style={{ margin: '8px 0' }}>
      {label && (
        <div style={{
          fontSize: '11px',
          color: 'var(--text-muted)',
          marginBottom: '4px',
          fontFamily: 'var(--font-mono)',
        }}>
          {label}
        </div>
      )}
      <div style={{ position: 'relative' }}>
        <pre style={{
          background: '#0d1117',
          borderRadius: 'var(--radius)',
          padding: '14px',
          overflowX: 'auto',
          border: '1px solid var(--border)',
          margin: 0,
        }}>
          <code ref={codeRef} className={`language-${language}`} style={{ fontSize: '12px' }}>
            {code}
          </code>
        </pre>
        <button
          onClick={handleCopy}
          title="Copy"
          style={{
            position: 'absolute',
            top: '8px',
            right: '8px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: copied ? 'var(--accent)' : 'var(--text-muted)',
            padding: '2px',
            display: 'flex',
            alignItems: 'center',
            transition: 'color 0.1s',
          }}
          onMouseEnter={e => { if (!copied) e.currentTarget.style.color = 'var(--accent)'; }}
          onMouseLeave={e => { if (!copied) e.currentTarget.style.color = 'var(--text-muted)'; }}
        >
          {copied ? <IconCheck size={14} stroke={2} /> : <IconCopy size={14} stroke={1.5} />}
        </button>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Rewrite `ScanCard.jsx`**

Status dot added. Target in mono, metadata in muted sans. Hover lifts border to green.

```jsx
// src/agentsec/dashboard/frontend/src/components/ScanCard.jsx
import { Link } from 'react-router-dom';

const STATUS_DOT = {
  scanning: { color: 'var(--accent)', pulse: true },
  complete:  { color: 'var(--accent)', pulse: false },
  error:     { color: 'var(--danger)', pulse: false },
};

function StatusDot({ status }) {
  const s = STATUS_DOT[status] ?? STATUS_DOT.complete;
  return (
    <span style={{
      display: 'inline-block',
      width: '6px',
      height: '6px',
      borderRadius: '50%',
      background: s.color,
      flexShrink: 0,
      ...(s.pulse ? { animation: 'pulse 1.5s ease-in-out infinite' } : {}),
    }} />
  );
}

export default function ScanCard({ scan }) {
  const status = scan.status ?? 'complete';

  return (
    <Link
      to={`/scans/${scan.scan_id}`}
      style={{
        display: 'block',
        background: 'var(--bg-surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: '12px 16px',
        textDecoration: 'none',
        transition: 'border-color 0.1s',
      }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--border-green)'; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <StatusDot status={status} />
          <span style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '13px',
            color: 'var(--text-primary)',
          }}>
            {scan.target}
          </span>
        </div>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>
          {new Date(scan.started_at).toLocaleString()}
        </span>
      </div>
      <div style={{ display: 'flex', gap: '16px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
        <span style={{ color: 'var(--text-muted)' }}>{scan.total_probes} probes</span>
        {scan.vulnerable_count > 0 && (
          <span style={{ color: 'var(--danger)' }}>{scan.vulnerable_count} vulnerable</span>
        )}
        {scan.resistant_count > 0 && (
          <span style={{ color: 'var(--accent)' }}>{scan.resistant_count} resistant</span>
        )}
        {scan.error_count > 0 && (
          <span style={{ color: 'var(--danger)', opacity: 0.7 }}>{scan.error_count} errors</span>
        )}
        <span style={{ color: 'var(--text-muted)' }}>{scan.duration_ms}ms</span>
      </div>
    </Link>
  );
}
```

- [ ] **Step 3: Verify build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add src/agentsec/dashboard/frontend/src/components/CodeBlock.jsx \
        src/agentsec/dashboard/frontend/src/components/ScanCard.jsx
git commit -m "FEAT: restyle CodeBlock (copy button) and ScanCard (status dot, token colors)"
```

---

## Task 5: ProbeProgress + AgentGraph

**Files:**
- Modify: `src/agentsec/dashboard/frontend/src/components/ProbeProgress.jsx`
- Modify: `src/agentsec/dashboard/frontend/src/components/AgentGraph.jsx`

- [ ] **Step 1: Rewrite `ProbeProgress.jsx`**

Replaces emoji status icons with Tabler icons. Spinning animation for running probes. Token-based colors.

```jsx
// src/agentsec/dashboard/frontend/src/components/ProbeProgress.jsx
import {
  IconRadar,
  IconCheck,
  IconX,
  IconAdjustments,
  IconPlayerSkipForward,
} from '@tabler/icons-react';

const STATUS_CONFIG = {
  started:   { Icon: IconRadar, color: 'var(--accent)', spin: true },
  vulnerable: { Icon: IconX, color: 'var(--danger)', spin: false },
  resistant:  { Icon: IconCheck, color: 'var(--accent)', spin: false },
  partial:    { Icon: IconAdjustments, color: '#fbbf24', spin: false },
  error:      { Icon: IconX, color: 'var(--danger)', spin: false },
  skipped:    { Icon: IconPlayerSkipForward, color: 'var(--text-muted)', spin: false },
};

function ProbeIcon({ status }) {
  const { Icon, color, spin } = STATUS_CONFIG[status] ?? STATUS_CONFIG.started;
  return (
    <span style={{
      color,
      display: 'flex',
      alignItems: 'center',
      ...(spin ? { animation: 'spin 1.2s linear infinite' } : {}),
    }}>
      <Icon size={14} stroke={1.5} />
    </span>
  );
}

export default function ProbeProgress({ events }) {
  const probes = {};
  for (const event of events) {
    if (event.type === 'scan_complete' || event.type === 'error') continue;
    const id = event.probe_id;
    if (!probes[id]) probes[id] = { probe_id: id, probe_name: event.probe_name };
    if (event.type === 'completed') {
      probes[id].status = event.status;
      probes[id].severity = event.severity;
      probes[id].duration_ms = event.duration_ms;
    }
  }

  return (
    <>
      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {Object.values(probes).map(probe => (
          <div
            key={probe.probe_id}
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: '8px 14px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ProbeIcon status={probe.status ?? 'started'} />
              <div>
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '12px',
                  color: 'var(--accent)',
                }}>
                  {probe.probe_id}
                </span>
                {probe.probe_name && (
                  <span style={{
                    fontSize: '11px',
                    color: 'var(--text-muted)',
                    marginLeft: '8px',
                    fontFamily: 'var(--font-sans)',
                  }}>
                    {probe.probe_name}
                  </span>
                )}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              {probe.status && (
                <span style={{
                  fontSize: '10px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  color: (STATUS_CONFIG[probe.status] ?? STATUS_CONFIG.started).color,
                }}>
                  {probe.status}
                </span>
              )}
              {probe.duration_ms != null && (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  {probe.duration_ms}ms
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
```

- [ ] **Step 2: Rewrite `AgentGraph.jsx`**

Reads token colors from CSS variables at render time so D3 respects the active theme. Supervisor nodes use accent green; retrieval nodes use blue; default uses surface-raised.

```jsx
// src/agentsec/dashboard/frontend/src/components/AgentGraph.jsx
import { useEffect, useRef } from 'react';
import * as d3 from 'd3';

function getCssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export default function AgentGraph({ agents }) {
  const svgRef = useRef(null);

  useEffect(() => {
    if (!agents || agents.length === 0 || !svgRef.current) return;

    const width = svgRef.current.clientWidth || 600;
    const height = 400;

    // Read theme-aware colors at render time
    const colBgRaised  = getCssVar('--bg-surface-raised') || '#111111';
    const colBorderGrn = getCssVar('--border-green')      || '#1a2a1a';
    const colAccent    = getCssVar('--accent')             || '#22c55e';
    const colTextMuted = getCssVar('--text-secondary')     || '#6b7280';
    const colEdge      = getCssVar('--accent-dim')         || '#166534';

    const nodeColor = (d) => {
      const role = (d.role || '').toLowerCase();
      if (role.includes('supervis')) return colAccent;
      if (role.includes('retriev'))  return '#60a5fa';
      return colBgRaised;
    };

    const nodes = agents.map(a => ({
      id: a.name,
      role: a.role,
      tools: a.tools || [],
      radius: 20 + (a.tools?.length || 0) * 5,
    }));

    const nodeIds = new Set(nodes.map(n => n.id));
    const links = [];
    for (const agent of agents) {
      for (const downstream of (agent.downstream_agents || [])) {
        if (nodeIds.has(downstream)) {
          links.push({ source: agent.name, target: downstream });
        }
      }
    }

    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('viewBox', [0, 0, width, height]);

    svg.append('defs').append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 25).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', colEdge);

    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(120))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => d.radius + 10));

    const link = svg.append('g')
      .selectAll('line').data(links).join('line')
      .attr('stroke', colEdge)
      .attr('stroke-width', 1)
      .attr('opacity', 0.6)
      .attr('marker-end', 'url(#arrowhead)');

    const node = svg.append('g')
      .selectAll('g').data(nodes).join('g')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end',   (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    node.append('circle')
      .attr('r', d => d.radius)
      .attr('fill', d => nodeColor(d))
      .attr('stroke', colBorderGrn)
      .attr('stroke-width', 1);

    node.append('text')
      .text(d => d.id)
      .attr('text-anchor', 'middle')
      .attr('dy', d => d.radius + 16)
      .attr('fill', colTextMuted)
      .attr('font-size', '11px')
      .attr('font-family', 'IBM Plex Mono, monospace');

    node.append('text')
      .text(d => d.tools.length > 0 ? `${d.tools.length} tools` : '')
      .attr('text-anchor', 'middle')
      .attr('dy', d => d.radius + 28)
      .attr('fill', colEdge)
      .attr('font-size', '9px')
      .attr('font-family', 'IBM Plex Sans, sans-serif');

    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    return () => simulation.stop();
  }, [agents]);

  if (!agents || agents.length === 0) {
    return (
      <p style={{ fontSize: '13px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>
        No agents discovered.
      </p>
    );
  }

  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '16px',
    }}>
      <h3 style={{
        fontSize: '11px',
        fontWeight: 600,
        color: 'var(--text-muted)',
        marginBottom: '12px',
        fontFamily: 'var(--font-sans)',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
      }}>
        Agent Topology
      </h3>
      <svg ref={svgRef} style={{ width: '100%', height: 400 }} />
    </div>
  );
}
```

- [ ] **Step 3: Verify build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add src/agentsec/dashboard/frontend/src/components/ProbeProgress.jsx \
        src/agentsec/dashboard/frontend/src/components/AgentGraph.jsx
git commit -m "FEAT: restyle ProbeProgress (Tabler + spin animation) and AgentGraph (CSS var colors)"
```

---

## Task 6: ScanForm + FindingFilters

**Files:**
- Modify: `src/agentsec/dashboard/frontend/src/components/ScanForm.jsx`
- Modify: `src/agentsec/dashboard/frontend/src/components/FindingFilters.jsx`

- [ ] **Step 1: Rewrite `ScanForm.jsx`**

Ghost-style submit button. Token-based inputs with focus ring. Checkbox labels remain functional.

```jsx
// src/agentsec/dashboard/frontend/src/components/ScanForm.jsx
import { useState, useEffect } from 'react';
import { fetchTargets } from '../api';

const inputStyle = {
  width: '100%',
  background: 'var(--bg-surface)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius)',
  padding: '7px 10px',
  fontSize: '13px',
  color: 'var(--text-primary)',
  fontFamily: 'var(--font-sans)',
  outline: 'none',
  boxSizing: 'border-box',
};

const labelStyle = {
  display: 'block',
  fontSize: '11px',
  color: 'var(--text-muted)',
  marginBottom: '5px',
  fontFamily: 'var(--font-sans)',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
};

export default function ScanForm({ onSubmit, loading }) {
  const [targets, setTargets] = useState([]);
  const [config, setConfig] = useState({
    target: '',
    adapter: 'langgraph',
    vulnerable: true,
    smart: false,
    live: false,
  });

  useEffect(() => {
    fetchTargets().then(data => {
      setTargets(data.targets || []);
      if (data.targets?.length > 0) {
        setConfig(prev => ({ ...prev, target: data.targets[0].path }));
      }
    });
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    onSubmit(config);
  };

  return (
    <form onSubmit={handleSubmit} style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '20px',
    }}>
      <h2 style={{
        fontSize: '13px',
        fontWeight: 600,
        color: 'var(--text-primary)',
        marginBottom: '16px',
        fontFamily: 'var(--font-sans)',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
      }}>
        New Scan
      </h2>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div>
          <label style={labelStyle}>Target</label>
          <select
            value={config.target}
            onChange={e => setConfig({ ...config, target: e.target.value })}
            style={inputStyle}
            onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
            onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
          >
            {targets.map(t => (
              <option key={t.path} value={t.path}>{t.name}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap' }}>
          {[
            { key: 'vulnerable', label: 'Vulnerable mode' },
            { key: 'smart', label: 'Smart payloads' },
            { key: 'live', label: 'Live LLM' },
          ].map(({ key, label }) => (
            <label key={key} style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '13px',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              fontFamily: 'var(--font-sans)',
            }}>
              <input
                type="checkbox"
                checked={config[key]}
                onChange={e => setConfig({ ...config, [key]: e.target.checked })}
                style={{ accentColor: 'var(--accent)', cursor: 'pointer' }}
              />
              {label}
            </label>
          ))}
        </div>

        <div>
          <button
            type="submit"
            disabled={loading || !config.target}
            style={{
              border: '1px solid var(--accent)',
              borderRadius: 'var(--radius)',
              padding: '7px 16px',
              fontSize: '13px',
              color: 'var(--accent)',
              background: 'transparent',
              cursor: loading || !config.target ? 'not-allowed' : 'pointer',
              fontFamily: 'var(--font-sans)',
              fontWeight: 500,
              opacity: loading || !config.target ? 0.4 : 1,
              transition: 'background 0.1s',
            }}
            onMouseEnter={e => { if (!loading && config.target) e.currentTarget.style.background = 'var(--success-bg)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
          >
            {loading ? 'Scanning...' : 'Start Scan'}
          </button>
        </div>
      </div>
    </form>
  );
}
```

- [ ] **Step 2: Rewrite `FindingFilters.jsx`**

Filter pills use token borders. Active pill: accent color and success-bg. Category pills use mono font.

```jsx
// src/agentsec/dashboard/frontend/src/components/FindingFilters.jsx
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['vulnerable', 'resistant', 'partial', 'error', 'skipped'];

function pillStyle(active) {
  return {
    padding: '2px 8px',
    borderRadius: 'var(--radius)',
    fontSize: '11px',
    fontFamily: 'var(--font-mono)',
    border: `1px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
    color: active ? 'var(--accent)' : 'var(--text-muted)',
    background: active ? 'var(--success-bg)' : 'transparent',
    cursor: 'pointer',
    transition: 'border-color 0.1s, color 0.1s',
  };
}

export default function FindingFilters({ findings, filters, onFilterChange }) {
  const categories = [...new Set(findings.map(f => f.category))].sort();

  const toggle = (key, value) => {
    const current = new Set(filters[key] || []);
    if (current.has(value)) current.delete(value);
    else current.add(value);
    onFilterChange({ ...filters, [key]: [...current] });
  };

  const isActive = (key, value) => {
    if (!filters[key] || filters[key].length === 0) return true;
    return filters[key].includes(value);
  };

  const groupLabel = {
    fontSize: '11px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-sans)',
    marginRight: '6px',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
  };

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
        <span style={groupLabel}>Status</span>
        {STATUSES.map(s => (
          <button key={s} onClick={() => toggle('statuses', s)} style={pillStyle(isActive('statuses', s))}>
            {s}
          </button>
        ))}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
        <span style={groupLabel}>Severity</span>
        {SEVERITIES.map(s => (
          <button key={s} onClick={() => toggle('severities', s)} style={pillStyle(isActive('severities', s))}>
            {s}
          </button>
        ))}
      </div>

      {categories.length > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
          <span style={groupLabel}>Category</span>
          {categories.map(c => (
            <button key={c} onClick={() => toggle('categories', c)} style={pillStyle(isActive('categories', c))}>
              {c}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Verify build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add src/agentsec/dashboard/frontend/src/components/ScanForm.jsx \
        src/agentsec/dashboard/frontend/src/components/FindingFilters.jsx
git commit -m "FEAT: restyle ScanForm (ghost button, token inputs) and FindingFilters (accent pills)"
```

---

## Task 7: SummaryTable + EmptyState + ErrorState + LoadingSkeleton

**Files:**
- Modify: `src/agentsec/dashboard/frontend/src/components/SummaryTable.jsx`
- Modify: `src/agentsec/dashboard/frontend/src/components/EmptyState.jsx`
- Modify: `src/agentsec/dashboard/frontend/src/components/ErrorState.jsx`
- Modify: `src/agentsec/dashboard/frontend/src/components/LoadingSkeleton.jsx`

- [ ] **Step 1: Rewrite `SummaryTable.jsx`**

Category code in mono accent. Zebra striping via surface tokens. Uppercase headers.

```jsx
// src/agentsec/dashboard/frontend/src/components/SummaryTable.jsx
const CATEGORY_NAMES = {
  ASI01: 'Agent Goal Hijacking',
  ASI02: 'Tool Misuse & Exploitation',
  ASI03: 'Identity & Privilege Abuse',
  ASI04: 'Supply Chain Vulnerabilities',
  ASI05: 'Output & Impact Control Failures',
  ASI06: 'Memory & Context Manipulation',
  ASI07: 'Multi-Agent Orchestration',
  ASI08: 'Uncontrolled Autonomous Execution',
  ASI09: 'Human-Agent Trust Exploitation',
  ASI10: 'Rogue Agent Behavior',
};

const thStyle = {
  padding: '8px 14px',
  fontSize: '10px',
  fontFamily: 'var(--font-sans)',
  color: 'var(--text-muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
  fontWeight: 600,
  textAlign: 'left',
  borderBottom: '1px solid var(--border)',
};

export default function SummaryTable({ findings }) {
  const categories = {};
  for (const f of findings) {
    const cat = f.category;
    if (!categories[cat]) categories[cat] = { total: 0, vulnerable: 0, resistant: 0, other: 0 };
    categories[cat].total++;
    if (f.status === 'vulnerable' || f.status === 'partial') categories[cat].vulnerable++;
    else if (f.status === 'resistant') categories[cat].resistant++;
    else categories[cat].other++;
  }

  const sorted = Object.entries(categories).sort(([a], [b]) => a.localeCompare(b));

  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      overflow: 'hidden',
    }}>
      <table style={{ width: '100%', fontSize: '13px', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={thStyle}>Category</th>
            <th style={{ ...thStyle, textAlign: 'center' }}>Probes</th>
            <th style={{ ...thStyle, textAlign: 'center' }}>Vulnerable</th>
            <th style={{ ...thStyle, textAlign: 'center' }}>Resistant</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map(([cat, counts], i) => (
            <tr key={cat} style={{
              background: i % 2 === 0 ? 'var(--bg-surface)' : 'var(--bg-surface-raised)',
              borderBottom: '1px solid var(--border)',
            }}>
              <td style={{ padding: '8px 14px' }}>
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  color: 'var(--accent)',
                  marginRight: '8px',
                }}>
                  {cat}
                </span>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-sans)' }}>
                  {CATEGORY_NAMES[cat] || cat}
                </span>
              </td>
              <td style={{ padding: '8px 14px', textAlign: 'center', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                {counts.total}
              </td>
              <td style={{ padding: '8px 14px', textAlign: 'center', fontFamily: 'var(--font-mono)', fontWeight: counts.vulnerable > 0 ? 600 : 400 }}>
                <span style={{ color: counts.vulnerable > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
                  {counts.vulnerable}
                </span>
              </td>
              <td style={{ padding: '8px 14px', textAlign: 'center', fontFamily: 'var(--font-mono)' }}>
                <span style={{ color: counts.resistant > 0 ? 'var(--accent)' : 'var(--text-muted)' }}>
                  {counts.resistant}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 2: Rewrite `EmptyState.jsx`**

```jsx
// src/agentsec/dashboard/frontend/src/components/EmptyState.jsx
import { Link } from 'react-router-dom';
import { IconInbox } from '@tabler/icons-react';

export default function EmptyState({ title, description, actionLabel, actionTo }) {
  return (
    <div style={{ textAlign: 'center', padding: '48px 24px' }}>
      <div style={{ color: 'var(--text-muted)', marginBottom: '16px', display: 'flex', justifyContent: 'center' }}>
        <IconInbox size={36} stroke={1} />
      </div>
      <h3 style={{
        fontSize: '15px',
        fontWeight: 600,
        color: 'var(--text-secondary)',
        marginBottom: '8px',
        fontFamily: 'var(--font-sans)',
      }}>
        {title}
      </h3>
      <p style={{
        fontSize: '13px',
        color: 'var(--text-muted)',
        marginBottom: '20px',
        fontFamily: 'var(--font-sans)',
      }}>
        {description}
      </p>
      {actionTo && (
        <Link
          to={actionTo}
          style={{
            display: 'inline-block',
            border: '1px solid var(--accent)',
            borderRadius: 'var(--radius)',
            padding: '6px 14px',
            fontSize: '13px',
            color: 'var(--accent)',
            textDecoration: 'none',
            fontFamily: 'var(--font-sans)',
          }}
        >
          {actionLabel || 'Get Started'}
        </Link>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Rewrite `ErrorState.jsx`**

```jsx
// src/agentsec/dashboard/frontend/src/components/ErrorState.jsx
import { IconAlertCircle } from '@tabler/icons-react';

export default function ErrorState({ message, onRetry }) {
  return (
    <div style={{
      background: 'var(--danger-bg)',
      border: '1px solid var(--border-red)',
      borderRadius: 'var(--radius)',
      padding: '24px',
      textAlign: 'center',
    }}>
      <div style={{ color: 'var(--danger)', marginBottom: '12px', display: 'flex', justifyContent: 'center' }}>
        <IconAlertCircle size={32} stroke={1.25} />
      </div>
      <p style={{
        color: 'var(--danger)',
        marginBottom: onRetry ? '16px' : 0,
        fontSize: '13px',
        fontFamily: 'var(--font-sans)',
      }}>
        {message || 'Something went wrong'}
      </p>
      {onRetry && (
        <button
          onClick={onRetry}
          style={{
            border: '1px solid var(--danger)',
            borderRadius: 'var(--radius)',
            padding: '6px 14px',
            fontSize: '13px',
            color: 'var(--danger)',
            background: 'transparent',
            cursor: 'pointer',
            fontFamily: 'var(--font-sans)',
          }}
        >
          Try Again
        </button>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Rewrite `LoadingSkeleton.jsx`**

```jsx
// src/agentsec/dashboard/frontend/src/components/LoadingSkeleton.jsx
const shimmer = {
  background: 'var(--bg-surface-raised)',
  borderRadius: 'var(--radius)',
  animation: 'pulse 1.5s ease-in-out infinite',
};

export function SkeletonCard() {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '14px 16px',
    }}>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }`}</style>
      <div style={{ ...shimmer, height: '13px', width: '60%', marginBottom: '10px' }} />
      <div style={{ ...shimmer, height: '11px', width: '35%' }} />
    </div>
  );
}

export function SkeletonTable({ rows = 4 }) {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      overflow: 'hidden',
    }}>
      <div style={{ height: '36px', background: 'var(--bg-surface-raised)', borderBottom: '1px solid var(--border)' }} />
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} style={{
          height: '36px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          padding: '0 14px',
          gap: '16px',
        }}>
          <div style={{ ...shimmer, height: '11px', width: '25%' }} />
          <div style={{ ...shimmer, height: '11px', width: '15%' }} />
          <div style={{ ...shimmer, height: '11px', width: '12%' }} />
        </div>
      ))}
    </div>
  );
}

export function SkeletonGraph() {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '16px',
      height: '400px',
    }}>
      <div style={{ ...shimmer, height: '12px', width: '20%', marginBottom: '16px' }} />
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        height: 'calc(100% - 40px)',
        color: 'var(--text-muted)',
        fontSize: '12px',
        fontFamily: 'var(--font-sans)',
      }}>
        Loading graph...
      </div>
    </div>
  );
}
```

- [ ] **Step 5: Verify build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/agentsec/dashboard/frontend/src/components/SummaryTable.jsx \
        src/agentsec/dashboard/frontend/src/components/EmptyState.jsx \
        src/agentsec/dashboard/frontend/src/components/ErrorState.jsx \
        src/agentsec/dashboard/frontend/src/components/LoadingSkeleton.jsx
git commit -m "FEAT: restyle SummaryTable, EmptyState, ErrorState, LoadingSkeleton with tokens and Tabler icons"
```

---

## ⚡ PARALLEL BATCH B — Tasks 8–12

> Dispatch all five tasks simultaneously after ALL of Batch A is committed. Each task touches only its own page file plus no shared components.

---

## Task 8: Dashboard Page

**Files:**
- Modify: `src/agentsec/dashboard/frontend/src/pages/Dashboard.jsx`

- [ ] **Step 1: Restyle `Dashboard.jsx`**

Section heading in mono uppercase. The rest of the page delegates to already-restyled components.

```jsx
// src/agentsec/dashboard/frontend/src/pages/Dashboard.jsx
import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import ScanForm from '../components/ScanForm';
import ScanCard from '../components/ScanCard';
import { SkeletonCard } from '../components/LoadingSkeleton';
import ErrorState from '../components/ErrorState';
import EmptyState from '../components/EmptyState';
import { startScan, fetchScans } from '../api';
import { useSettings } from '../hooks/useSettings';

export default function Dashboard() {
  const navigate = useNavigate();
  const { settings } = useSettings();
  const [loading, setLoading] = useState(false);
  const [scanError, setScanError] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [scansLoading, setScansLoading] = useState(true);
  const [scansError, setScansError] = useState(null);

  const loadScans = useCallback(() => {
    setScansLoading(true);
    setScansError(null);
    fetchScans(5)
      .then(data => setRecentScans(data.scans || []))
      .catch(err => setScansError(err.message || 'Failed to load recent scans'))
      .finally(() => setScansLoading(false));
  }, []);

  useEffect(() => { loadScans(); }, [loadScans]);

  const handleScan = async (config) => {
    setLoading(true);
    setScanError(null);
    try {
      const mergedConfig = {
        ...config,
        llm_model: settings.llm_model,
        target_model: settings.target_model || undefined,
        openrouter_api_key: settings.openrouter_api_key || undefined,
      };
      const data = await startScan(mergedConfig);
      navigate(`/scans/${data.scan_id}/progress`);
    } catch (err) {
      setScanError(err.message || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      <ScanForm onSubmit={handleScan} loading={loading} />

      {scanError && <ErrorState message={scanError} onRetry={null} />}

      <div>
        <h2 style={{
          fontSize: '11px',
          fontWeight: 600,
          color: 'var(--text-muted)',
          fontFamily: 'var(--font-sans)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          marginBottom: '10px',
        }}>
          Recent Scans
        </h2>

        {scansLoading && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <SkeletonCard /><SkeletonCard /><SkeletonCard />
          </div>
        )}

        {!scansLoading && scansError && (
          <ErrorState message={scansError} onRetry={loadScans} />
        )}

        {!scansLoading && !scansError && recentScans.length === 0 && (
          <EmptyState
            title="No scans yet"
            description="Run your first scan to see results here."
            actionLabel="Start Scanning"
            actionTo="/"
          />
        )}

        {!scansLoading && !scansError && recentScans.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {recentScans.map(scan => (
              <ScanCard key={scan.scan_id} scan={scan} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Verify build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/agentsec/dashboard/frontend/src/pages/Dashboard.jsx
git commit -m "FEAT: restyle Dashboard page with token-based layout"
```

---

## Task 9: ScanProgress Page

**Files:**
- Modify: `src/agentsec/dashboard/frontend/src/pages/ScanProgress.jsx`

- [ ] **Step 1: Restyle `ScanProgress.jsx`**

Stats grid uses token colors. "View Results" uses ghost button style. Context panel shows Progress / Summary sections.

```jsx
// src/agentsec/dashboard/frontend/src/pages/ScanProgress.jsx
import { useParams, useNavigate } from 'react-router-dom';
import { useScanStream } from '../hooks/useScanStream';
import ProbeProgress from '../components/ProbeProgress';
import ErrorState from '../components/ErrorState';
import ContextPanel from '../components/ContextPanel';

const SECTIONS = [
  { id: 'progress', label: 'Progress' },
  { id: 'summary', label: 'Summary' },
];

function StatCard({ label, value, color }) {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '14px',
      textAlign: 'center',
    }}>
      <div style={{
        fontSize: '22px',
        fontWeight: 600,
        fontFamily: 'var(--font-mono)',
        color: color || 'var(--text-primary)',
        marginBottom: '4px',
      }}>
        {value}
      </div>
      <div style={{
        fontSize: '10px',
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-sans)',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
      }}>
        {label}
      </div>
    </div>
  );
}

export default function ScanProgress() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { events, status } = useScanStream(id);

  const completion = events.find(e => e.type === 'scan_complete');
  const scanErrorEvent = events.find(e => e.type === 'error');

  if (status === 'error') {
    const errorMessage = scanErrorEvent?.message || 'The scan encountered an unexpected error.';
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <ErrorState message={errorMessage} />
        <div style={{ textAlign: 'center' }}>
          <button
            onClick={() => navigate('/')}
            style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', color: 'var(--accent)', fontFamily: 'var(--font-sans)' }}
          >
            ← Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', gap: '24px' }}>
      <ContextPanel sections={completion ? SECTIONS : [SECTIONS[0]]} />

      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <h1 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-sans)' }}>
            {status === 'complete' ? 'Scan Complete' : 'Scanning...'}
          </h1>
          {status === 'complete' && (
            <button
              onClick={() => navigate(`/scans/${id}`)}
              style={{
                border: '1px solid var(--accent)',
                borderRadius: 'var(--radius)',
                padding: '6px 14px',
                fontSize: '13px',
                color: 'var(--accent)',
                background: 'transparent',
                cursor: 'pointer',
                fontFamily: 'var(--font-sans)',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = 'var(--success-bg)'; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
            >
              View Results →
            </button>
          )}
        </div>

        {completion && (
          <div id="summary" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
            <StatCard label="Total" value={completion.total} />
            <StatCard label="Vulnerable" value={completion.vulnerable} color="var(--danger)" />
            <StatCard label="Resistant" value={completion.resistant} color="var(--accent)" />
            <StatCard label="Errors" value={completion.error} color="var(--danger)" />
          </div>
        )}

        <div id="progress">
          <ProbeProgress events={events} />
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Verify build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/agentsec/dashboard/frontend/src/pages/ScanProgress.jsx
git commit -m "FEAT: restyle ScanProgress page with token stat cards and ContextPanel"
```

---

## Task 10: ScanDetail Page

**Files:**
- Modify: `src/agentsec/dashboard/frontend/src/pages/ScanDetail.jsx`

- [ ] **Step 1: Restyle `ScanDetail.jsx`**

Adds ContextPanel. Delete moves to a discreet button in header. Section headings get anchors for jump-nav.

```jsx
// src/agentsec/dashboard/frontend/src/pages/ScanDetail.jsx
import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { fetchScan, deleteScan } from '../api';
import { SkeletonTable, SkeletonGraph } from '../components/LoadingSkeleton';
import ErrorState from '../components/ErrorState';
import SummaryTable from '../components/SummaryTable';
import AgentGraph from '../components/AgentGraph';
import FindingCard from '../components/FindingCard';
import FindingFilters from '../components/FindingFilters';
import ContextPanel from '../components/ContextPanel';

const SECTIONS = [
  { id: 'stats', label: 'Stats' },
  { id: 'topology', label: 'Topology' },
  { id: 'summary', label: 'Summary' },
  { id: 'findings', label: 'Findings' },
];

function StatCard({ label, value, color }) {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '14px',
      textAlign: 'center',
    }}>
      <div style={{
        fontSize: '22px',
        fontWeight: 600,
        fontFamily: 'var(--font-mono)',
        color: color || 'var(--text-primary)',
        marginBottom: '4px',
      }}>
        {value}
      </div>
      <div style={{
        fontSize: '10px',
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-sans)',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
      }}>
        {label}
      </div>
    </div>
  );
}

function SectionHeading({ id, children }) {
  return (
    <h2 id={id} style={{
      fontSize: '11px',
      fontWeight: 600,
      color: 'var(--text-muted)',
      fontFamily: 'var(--font-sans)',
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
      marginBottom: '10px',
    }}>
      {children}
    </h2>
  );
}

export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);
  const [deleteError, setDeleteError] = useState(null);
  const [filters, setFilters] = useState({ statuses: [], severities: [], categories: [] });

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchScan(id);
        setScan(data);
      } catch (err) {
        setError(err.message || 'Failed to load scan');
      }
    };
    load();
  }, [id]);

  const handleDelete = async () => {
    setDeleteError(null);
    try {
      await deleteScan(id);
      navigate('/scans');
    } catch (err) {
      setDeleteError(err.message || 'Failed to delete scan');
    }
  };

  if (error) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <ErrorState message={error} />
        <div style={{ textAlign: 'center' }}>
          <button onClick={() => navigate('/scans')}
            style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', color: 'var(--accent)', fontFamily: 'var(--font-sans)' }}>
            ← Back to scans
          </button>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div style={{ height: '22px', background: 'var(--bg-surface-raised)', borderRadius: 'var(--radius)', width: '33%', animation: 'pulse 1.5s ease-in-out infinite' }} />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', height: '72px', animation: 'pulse 1.5s ease-in-out infinite' }} />
          ))}
        </div>
        <SkeletonGraph />
        <SkeletonTable />
      </div>
    );
  }

  const findings = scan.findings || [];
  const filtered = findings.filter(f => {
    if (filters.statuses.length > 0 && !filters.statuses.includes(f.status)) return false;
    if (filters.severities.length > 0 && !filters.severities.includes(f.severity)) return false;
    if (filters.categories.length > 0 && !filters.categories.includes(f.category)) return false;
    return true;
  });

  return (
    <div style={{ display: 'flex', gap: '24px' }}>
      <ContextPanel sections={SECTIONS} />

      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: '24px' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
              {scan.target || 'Scan Result'}
            </h1>
            <p style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>
              {new Date(scan.started_at).toLocaleString()} · {scan.duration_ms}ms · {scan.total_probes} probes
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <button
              onClick={handleDelete}
              style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '12px', color: 'var(--danger)', fontFamily: 'var(--font-sans)', opacity: 0.7 }}
              onMouseEnter={e => { e.currentTarget.style.opacity = '1'; }}
              onMouseLeave={e => { e.currentTarget.style.opacity = '0.7'; }}
            >
              Delete
            </button>
            <Link to="/scans" style={{ fontSize: '12px', color: 'var(--accent)', fontFamily: 'var(--font-sans)', textDecoration: 'none' }}>
              ← All scans
            </Link>
          </div>
        </div>

        {deleteError && (
          <div style={{
            background: 'var(--danger-bg)',
            border: '1px solid var(--border-red)',
            borderRadius: 'var(--radius)',
            padding: '10px 14px',
            fontSize: '12px',
            color: 'var(--danger)',
            fontFamily: 'var(--font-sans)',
          }}>
            Failed to delete scan: {deleteError}
          </div>
        )}

        {/* Stats */}
        <div id="stats" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
          <StatCard label="Total" value={scan.total_probes} />
          <StatCard label="Vulnerable" value={scan.vulnerable_count} color="var(--danger)" />
          <StatCard label="Resistant" value={scan.resistant_count} color="var(--accent)" />
          <StatCard label="Errors" value={scan.error_count} color="var(--danger)" />
        </div>

        {/* Agent topology */}
        {scan.agents_discovered?.length > 0 && (
          <div id="topology">
            <SectionHeading id="topology-label">Agent Topology</SectionHeading>
            <AgentGraph agents={scan.agents_discovered} />
          </div>
        )}

        {/* Summary table */}
        {findings.length > 0 && (
          <div id="summary">
            <SectionHeading id="summary-label">Summary</SectionHeading>
            <SummaryTable findings={findings} />
          </div>
        )}

        {/* Findings */}
        {findings.length > 0 && (
          <div id="findings" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <SectionHeading id="findings-label">Findings</SectionHeading>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {filtered.length}/{findings.length}
              </span>
            </div>
            <FindingFilters findings={findings} filters={filters} onFilterChange={setFilters} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {filtered.map((f, i) => (
                <FindingCard key={`${f.probe_id}-${i}`} finding={f} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Verify build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/agentsec/dashboard/frontend/src/pages/ScanDetail.jsx
git commit -m "FEAT: restyle ScanDetail with ContextPanel, anchored sections, token stat cards"
```

---

## Task 11: ScanHistory Page

**Files:**
- Modify: `src/agentsec/dashboard/frontend/src/pages/ScanHistory.jsx`

- [ ] **Step 1: Restyle `ScanHistory.jsx`**

Sort buttons use active token styles. Delete button reveals on row hover via React state. Count footer in muted mono.

```jsx
// src/agentsec/dashboard/frontend/src/pages/ScanHistory.jsx
import { useState, useEffect, useCallback } from 'react';
import ScanCard from '../components/ScanCard';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';
import { SkeletonCard } from '../components/LoadingSkeleton';
import { fetchScans, deleteScan } from '../api';

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sortBy, setSortBy] = useState('date');
  const [hoveredId, setHoveredId] = useState(null);

  const loadScans = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchScans(100);
      setScans(data.scans || []);
    } catch (err) {
      setError(err.message || 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadScans(); }, [loadScans]);

  const handleDelete = async (scanId) => {
    if (!confirm('Delete this scan?')) return;
    try {
      await deleteScan(scanId);
      setScans(prev => prev.filter(s => s.scan_id !== scanId));
    } catch (err) {
      setError(err.message || 'Failed to delete scan');
    }
  };

  const sorted = [...scans].sort((a, b) => {
    if (sortBy === 'vulnerabilities') return b.vulnerable_count - a.vulnerable_count;
    if (sortBy === 'probes') return b.total_probes - a.total_probes;
    return new Date(b.started_at) - new Date(a.started_at);
  });

  if (error) return <ErrorState message={error} onRetry={loadScans} />;

  const sortButtonStyle = (s) => ({
    padding: '3px 8px',
    borderRadius: 'var(--radius)',
    fontSize: '11px',
    fontFamily: 'var(--font-mono)',
    border: '1px solid transparent',
    cursor: 'pointer',
    background: sortBy === s ? 'var(--bg-surface-raised)' : 'transparent',
    color: sortBy === s ? 'var(--text-primary)' : 'var(--text-muted)',
    transition: 'color 0.1s',
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h1 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-sans)' }}>
          Scan History
        </h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)', marginRight: '4px' }}>Sort:</span>
          {['date', 'vulnerabilities', 'probes'].map(s => (
            <button key={s} onClick={() => setSortBy(s)} style={sortButtonStyle(s)}>
              {s}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {Array.from({ length: 5 }).map((_, i) => <SkeletonCard key={i} />)}
        </div>
      ) : sorted.length === 0 ? (
        <EmptyState
          title="No scans yet"
          description="Run your first scan to see results here."
          actionLabel="Start Scanning"
          actionTo="/"
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {sorted.map(scan => (
            <div
              key={scan.scan_id}
              style={{ position: 'relative' }}
              onMouseEnter={() => setHoveredId(scan.scan_id)}
              onMouseLeave={() => setHoveredId(null)}
            >
              <ScanCard scan={scan} />
              <button
                onClick={(e) => { e.preventDefault(); handleDelete(scan.scan_id); }}
                style={{
                  position: 'absolute',
                  top: '12px',
                  right: '12px',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  fontSize: '11px',
                  color: 'var(--danger)',
                  fontFamily: 'var(--font-sans)',
                  opacity: hoveredId === scan.scan_id ? 1 : 0,
                  transition: 'opacity 0.1s',
                  pointerEvents: hoveredId === scan.scan_id ? 'auto' : 'none',
                }}
              >
                Delete
              </button>
            </div>
          ))}
        </div>
      )}

      {scans.length > 0 && (
        <div style={{ fontSize: '11px', color: 'var(--text-muted)', textAlign: 'center', paddingTop: '8px', fontFamily: 'var(--font-mono)' }}>
          {scans.length} scan{scans.length !== 1 ? 's' : ''}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Verify build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/agentsec/dashboard/frontend/src/pages/ScanHistory.jsx
git commit -m "FEAT: restyle ScanHistory with token sort buttons and delete hover"
```

---

## Task 12: Settings Page

**Files:**
- Modify: `src/agentsec/dashboard/frontend/src/pages/Settings.jsx`

- [ ] **Step 1: Restyle `Settings.jsx`**

All form elements use token-based styles. API key input in mono. Save button ghost style with green accent.

```jsx
// src/agentsec/dashboard/frontend/src/pages/Settings.jsx
import { useState, useEffect } from 'react';
import { IconCheck } from '@tabler/icons-react';
import { useSettings } from '../hooks/useSettings';

const MODELS = [
  { value: 'anthropic/claude-sonnet-4-6', label: 'Claude Sonnet 4.6 (recommended)' },
  { value: 'anthropic/claude-opus-4-6', label: 'Claude Opus 4.6 (most capable)' },
  { value: 'anthropic/claude-haiku-4-5', label: 'Claude Haiku 4.5 (fastest)' },
  { value: 'openai/gpt-4o', label: 'GPT-4o' },
  { value: 'openai/gpt-4o-mini', label: 'GPT-4o Mini' },
  { value: 'google/gemini-2.0-flash-001', label: 'Gemini 2.0 Flash' },
];

const TARGET_MODELS = [
  { value: 'openai/gpt-4.1-nano', label: 'GPT-4.1 Nano (fast, cheap — good default)' },
  { value: 'openai/gpt-4o-mini', label: 'GPT-4o Mini' },
  { value: 'openai/gpt-4o', label: 'GPT-4o' },
  { value: 'anthropic/claude-haiku-4-5', label: 'Claude Haiku 4.5' },
  { value: 'anthropic/claude-sonnet-4-6', label: 'Claude Sonnet 4.6' },
  { value: 'google/gemini-2.0-flash-001', label: 'Gemini 2.0 Flash' },
  { value: 'meta-llama/llama-3.3-70b-instruct', label: 'Llama 3.3 70B' },
];

const fieldLabel = {
  fontSize: '11px',
  color: 'var(--text-muted)',
  fontFamily: 'var(--font-sans)',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  display: 'block',
  marginBottom: '5px',
};

const fieldHint = {
  fontSize: '11px',
  color: 'var(--text-muted)',
  fontFamily: 'var(--font-sans)',
  marginBottom: '6px',
  lineHeight: 1.5,
};

const inputBase = {
  width: '100%',
  background: 'var(--bg-page)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius)',
  padding: '7px 10px',
  fontSize: '13px',
  color: 'var(--text-primary)',
  outline: 'none',
  boxSizing: 'border-box',
};

export default function Settings() {
  const { settings, updateSettings } = useSettings();
  const [saved, setSaved] = useState(false);
  const [form, setForm] = useState(settings);

  useEffect(() => { setForm(settings); }, [settings]);

  const handleSave = (e) => {
    e.preventDefault();
    updateSettings(form);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div style={{ maxWidth: '520px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <h1 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-sans)' }}>
        Settings
      </h1>

      <form onSubmit={handleSave} style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '18px',
      }}>
        <div>
          <label style={fieldLabel}>LLM Model</label>
          <p style={fieldHint}>Used for smart payload generation. Requires an OpenRouter API key.</p>
          <select
            value={form.llm_model}
            onChange={e => setForm({ ...form, llm_model: e.target.value })}
            style={{ ...inputBase, fontFamily: 'var(--font-sans)' }}
            onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
            onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
          >
            {MODELS.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
          </select>
        </div>

        <div>
          <label style={fieldLabel}>Target Model</label>
          <p style={fieldHint}>The LLM running <em>inside</em> your agent under test. Only used when <strong>Live LLM</strong> is enabled on a scan.</p>
          <select
            value={form.target_model}
            onChange={e => setForm({ ...form, target_model: e.target.value })}
            style={{ ...inputBase, fontFamily: 'var(--font-sans)' }}
            onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
            onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
          >
            {TARGET_MODELS.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
          </select>
        </div>

        <div>
          <label style={fieldLabel}>OpenRouter API Key</label>
          <p style={fieldHint}>
            Required for smart mode scans. Get one at{' '}
            <a href="https://openrouter.ai" target="_blank" rel="noopener noreferrer"
               style={{ color: 'var(--accent)', fontFamily: 'var(--font-sans)' }}>
              openrouter.ai
            </a>.
            Stored in your browser's localStorage only.
          </p>
          <input
            type="password"
            value={form.openrouter_api_key}
            onChange={e => setForm({ ...form, openrouter_api_key: e.target.value })}
            placeholder="sk-or-..."
            style={{ ...inputBase, fontFamily: 'var(--font-mono)' }}
            onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
            onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            type="submit"
            style={{
              border: '1px solid var(--accent)',
              borderRadius: 'var(--radius)',
              padding: '7px 16px',
              fontSize: '13px',
              color: 'var(--accent)',
              background: 'transparent',
              cursor: 'pointer',
              fontFamily: 'var(--font-sans)',
              fontWeight: 500,
              transition: 'background 0.1s',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'var(--success-bg)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
          >
            Save Settings
          </button>
          {saved && (
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '13px', color: 'var(--accent)', fontFamily: 'var(--font-sans)' }}>
              <IconCheck size={14} stroke={2} /> Saved
            </span>
          )}
        </div>
      </form>

      <div style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: '14px',
        fontSize: '11px',
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-sans)',
        display: 'flex',
        flexDirection: 'column',
        gap: '5px',
        lineHeight: 1.6,
      }}>
        <p style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>About API Keys</p>
        <p>Your API key is stored only in this browser's localStorage and never sent to any server other than OpenRouter (via the agentsec backend when running smart scans).</p>
        <p>Smart mode is off by default. Enable it per-scan in the scan form.</p>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Verify build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/agentsec/dashboard/frontend/src/pages/Settings.jsx
git commit -m "FEAT: restyle Settings page with token-based form fields and ghost save button"
```

---

## Final Verification

After all 12 tasks are committed, run a final build and dev server check:

- [ ] **Full build**

```bash
cd src/agentsec/dashboard/frontend && npm run build
```

Expected: clean build, no errors, no undefined variable warnings.

- [ ] **Start dev server and visually verify**

```bash
cd src/agentsec/dashboard/frontend && npm run dev
```

Open http://localhost:5173 and check:
1. Dark mode default — deep black background, IBM Plex fonts, green AGENTSEC wordmark
2. Theme toggle switches to warm off-white light mode (no longer broken)
3. Nav icons visible (Tabler), no emoji anywhere in the UI
4. Dashboard → ScanForm renders with ghost button
5. ScanHistory → ScanCard shows mono target path, status dot
6. Any scan detail → ContextPanel appears on left with jump links
7. Finding cards show left border accent (red for vuln, green-dim for resistant)
8. CodeBlock copy button works

- [ ] **Commit any final touch-ups**

```bash
git add -p  # stage only what you changed
git commit -m "MAINT: final polish after full UI rework verification"
```
