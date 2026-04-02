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
