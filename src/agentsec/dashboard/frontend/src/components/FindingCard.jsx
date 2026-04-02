import { useState } from 'react';
import { IconChevronDown, IconChevronUp } from '@tabler/icons-react';
import { SeverityBadge, StatusBadge } from './SeverityBadge';
import FindingDetail from './FindingDetail';

const LEFT_BORDER = {
  vulnerable: 'var(--danger)',
  resistant:  'var(--accent-dim)',
  partial:    'var(--warning)',
  error:      'var(--danger)',
  skipped:    'var(--border)',
};

export default function FindingCard({ finding, scanId, onOverrideChange }) {
  const [expanded, setExpanded] = useState(false);
  const [hovered, setHovered] = useState(false);
  const effectiveStatus = finding.override?.new_status ?? finding.status;
  const isOverridden = !!finding.override;
  const accentColor = LEFT_BORDER[effectiveStatus] ?? 'var(--border)';

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
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        style={{
          width: '100%',
          padding: '10px 14px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: hovered ? 'var(--bg-surface-raised)' : 'none',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
          transition: 'background 0.1s',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <StatusBadge status={effectiveStatus} overridden={isOverridden} />
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
          <FindingDetail finding={finding} scanId={scanId} onOverrideChange={onOverrideChange} />
        </div>
      )}
    </div>
  );
}
