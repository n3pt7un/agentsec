import { useState } from 'react';
import { Link } from 'react-router-dom';

const STATUS_DOT = {
  scanning: { color: 'var(--accent)', pulse: true },
  complete:  { color: 'var(--accent)', pulse: false },
  error:     { color: 'var(--danger)', pulse: false },
};

function StatusDot({ status }) {
  const s = STATUS_DOT[status] ?? STATUS_DOT.complete;
  return (
    <>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }`}</style>
      <span style={{
        display: 'inline-block',
        width: '6px',
        height: '6px',
        borderRadius: '50%',
        background: s.color,
        flexShrink: 0,
        ...(s.pulse ? { animation: 'pulse 1.5s ease-in-out infinite' } : {}),
      }} />
    </>
  );
}

export default function ScanCard({ scan }) {
  const [hovered, setHovered] = useState(false);
  const status = scan.status ?? 'complete';

  return (
    <Link
      to={`/scans/${scan.scan_id}`}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        display: 'block',
        background: 'var(--bg-surface)',
        border: `1px solid ${hovered ? 'var(--border-green)' : 'var(--border)'}`,
        borderRadius: 'var(--radius)',
        padding: '12px 16px',
        textDecoration: 'none',
        transition: 'border-color 0.1s',
      }}
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
