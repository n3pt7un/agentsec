import {
  IconAlertTriangle,
  IconShieldCheck,
  IconAdjustments,
  IconX,
  IconPlayerSkipForward,
  IconPencil,
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
  partial:    { color: 'var(--warning)', bg: 'var(--warning-bg)', border: 'var(--warning-bg)', Icon: IconAdjustments },
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

export function StatusBadge({ status, overridden = false }) {
  const s = STATUS_CONFIG[status] ?? STATUS_CONFIG.skipped;
  const { Icon } = s;
  const color = overridden ? 'var(--warning)' : s.color;
  const bg = overridden ? 'var(--warning-bg)' : s.bg;
  const border = overridden ? 'var(--warning-bg)' : s.border;
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '3px',
      padding: '1px 6px',
      borderRadius: 'var(--radius)',
      border: `1px solid ${border}`,
      background: bg,
      color: color,
      fontSize: '10px',
      fontFamily: 'var(--font-mono)',
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: '0.06em',
    }}>
      {overridden ? <IconPencil size={9} stroke={2} /> : <Icon size={10} stroke={2} />}
      {status}
    </span>
  );
}
