import { useState } from 'react';
import { IconPencil, IconAdjustments } from '@tabler/icons-react';
import CodeBlock from './CodeBlock';
import { applyOverride, removeOverride } from '../api';

const ALL_STATUSES = ['vulnerable', 'resistant', 'partial', 'error', 'skipped'];

function OverrideSection({ finding, scanId, onOverrideChange }) {
  const [mode, setMode] = useState('view'); // 'view' | 'form'
  const [newStatus, setNewStatus] = useState('');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [removeHovered, setRemoveHovered] = useState(false);
  const [applyHovered, setApplyHovered] = useState(false);

  const effectiveStatus = finding.override?.new_status ?? finding.status;
  const availableStatuses = ALL_STATUSES.filter(s => s !== effectiveStatus);

  const handleApply = async () => {
    if (!reason.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      const updated = await applyOverride(scanId, finding.probe_id, {
        new_status: newStatus || availableStatuses[0],
        reason: reason.trim(),
      });
      onOverrideChange?.(updated);
      setMode('view');
      setReason('');
      setNewStatus('');
    } catch (err) {
      setError(err.message || 'Failed to apply override');
    } finally {
      setSubmitting(false);
    }
  };

  const handleRemove = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await removeOverride(scanId, finding.probe_id);
      onOverrideChange?.({ ...finding, override: null });
      setMode('view');
    } catch (err) {
      setError(err.message || 'Failed to remove override');
    } finally {
      setSubmitting(false);
    }
  };

  const headingStyle = {
    fontSize: '10px',
    fontWeight: 600,
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-sans)',
    textTransform: 'uppercase',
    letterSpacing: '0.08em',
    marginBottom: '8px',
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
  };

  if (finding.override) {
    const o = finding.override;
    return (
      <div>
        <div style={headingStyle}>
          <IconPencil size={10} stroke={2} />
          Analyst Override
        </div>
        <div style={{
          background: 'var(--warning-bg)',
          border: '1px solid var(--warning)',
          borderRadius: 'var(--radius)',
          padding: '10px 12px',
          fontSize: '12px',
          fontFamily: 'var(--font-sans)',
          display: 'flex',
          flexDirection: 'column',
          gap: '5px',
          marginBottom: '8px',
        }}>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span style={{ color: 'var(--text-muted)', minWidth: '110px' }}>Original status:</span>
            <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{o.original_status}</span>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span style={{ color: 'var(--text-muted)', minWidth: '110px' }}>Overridden to:</span>
            <span style={{ color: 'var(--warning)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{o.new_status}</span>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span style={{ color: 'var(--text-muted)', minWidth: '110px' }}>Reason:</span>
            <span style={{ color: 'var(--text-secondary)', fontStyle: 'italic' }}>{o.reason}</span>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span style={{ color: 'var(--text-muted)', minWidth: '110px' }}>By:</span>
            <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{o.overridden_by}</span>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span style={{ color: 'var(--text-muted)', minWidth: '110px' }}>At:</span>
            <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
              {new Date(o.overridden_at).toLocaleString()}
            </span>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span style={{ color: 'var(--text-muted)', minWidth: '110px' }}>Compliance:</span>
            <span style={{ color: 'var(--warning)', fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 600 }}>FLAGGED</span>
          </div>
        </div>
        {error && <p style={{ fontSize: '12px', color: 'var(--danger)', fontFamily: 'var(--font-sans)', marginBottom: '6px' }}>{error}</p>}
        <button
          onClick={handleRemove}
          disabled={submitting}
          onMouseEnter={() => setRemoveHovered(true)}
          onMouseLeave={() => setRemoveHovered(false)}
          style={{
            background: 'none',
            border: 'none',
            cursor: submitting ? 'not-allowed' : 'pointer',
            fontSize: '11px',
            color: 'var(--danger)',
            fontFamily: 'var(--font-sans)',
            opacity: submitting ? 0.4 : (removeHovered ? 1 : 0.7),
            transition: 'opacity 0.1s',
            padding: 0,
          }}
        >
          {submitting ? 'Removing...' : 'Remove override'}
        </button>
      </div>
    );
  }

  if (mode === 'form') {
    const selectedStatus = newStatus || availableStatuses[0];
    return (
      <div>
        <div style={headingStyle}>
          <IconAdjustments size={10} stroke={2} />
          Override Status
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <select
            value={selectedStatus}
            onChange={e => setNewStatus(e.target.value)}
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: '5px 8px',
              fontSize: '12px',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-mono)',
              outline: 'none',
            }}
            onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
            onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
          >
            {availableStatuses.map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <textarea
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="Reason (required)"
            rows={3}
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: '6px 8px',
              fontSize: '12px',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-sans)',
              resize: 'vertical',
              outline: 'none',
            }}
            onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
            onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
          />
          {error && <p style={{ fontSize: '12px', color: 'var(--danger)', fontFamily: 'var(--font-sans)' }}>{error}</p>}
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={handleApply}
              disabled={submitting || !reason.trim()}
              onMouseEnter={() => setApplyHovered(true)}
              onMouseLeave={() => setApplyHovered(false)}
              style={{
                border: '1px solid var(--accent)',
                borderRadius: 'var(--radius)',
                padding: '4px 12px',
                fontSize: '12px',
                color: 'var(--accent)',
                background: applyHovered && !submitting && reason.trim() ? 'var(--success-bg)' : 'transparent',
                cursor: submitting || !reason.trim() ? 'not-allowed' : 'pointer',
                fontFamily: 'var(--font-sans)',
                opacity: submitting || !reason.trim() ? 0.4 : 1,
                transition: 'background 0.1s',
              }}
            >
              {submitting ? 'Applying...' : 'Apply'}
            </button>
            <button
              onClick={() => { setMode('view'); setReason(''); setNewStatus(''); setError(null); }}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                fontSize: '12px',
                color: 'var(--text-muted)',
                fontFamily: 'var(--font-sans)',
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    );
  }

  // mode === 'view', no override
  return (
    <div>
      <button
        onClick={() => setMode('form')}
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          fontSize: '11px',
          color: 'var(--text-muted)',
          fontFamily: 'var(--font-sans)',
          display: 'flex',
          alignItems: 'center',
          gap: '4px',
          padding: 0,
          transition: 'color 0.1s',
        }}
        onMouseEnter={e => { e.currentTarget.style.color = 'var(--text-secondary)'; }}
        onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; }}
      >
        <IconAdjustments size={11} stroke={1.5} />
        Override status
      </button>
    </div>
  );
}

export default function FindingDetail({ finding, scanId, onOverrideChange }) {
  const { evidence, remediation } = finding;
  const isResistant = finding.status === 'resistant';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px', borderTop: '1px solid var(--border)' }}>
      {/* Evidence / Interaction Log */}
      {evidence && (
        <div>
          <h4 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', fontFamily: 'var(--font-sans)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {isResistant ? 'Interaction Log' : 'Evidence'}
          </h4>
          <div style={{
            background: 'var(--bg-page)',
            border: `1px solid ${isResistant ? 'var(--border-green)' : 'var(--border)'}`,
            borderRadius: 'var(--radius)',
            padding: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            fontSize: '12px',
          }}>
            <div>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Attack input: </span>
              <code style={{ color: isResistant ? 'var(--text-secondary)' : 'var(--danger)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{evidence.attack_input}</code>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Target agent: </span>
              <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>{evidence.target_agent}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Response: </span>
              <code style={{ color: isResistant ? 'var(--accent)' : 'var(--warning)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{evidence.agent_response}</code>
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

      {/* Blast radius — only for vulnerable/partial */}
      {!isResistant && finding.blast_radius && (
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

      {/* Remediation — only for vulnerable/partial */}
      {!isResistant && remediation && (
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
                <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                   style={{ fontSize: '11px', color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
                  {ref}
                </a>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Analyst Override */}
      <div style={{ paddingTop: '16px', borderTop: '1px solid var(--border)' }}>
        <OverrideSection
          finding={finding}
          scanId={scanId}
          onOverrideChange={onOverrideChange}
        />
      </div>
    </div>
  );
}
