import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useScanStream } from '../hooks/useScanStream';
import ProbeProgress from '../components/ProbeProgress';
import ErrorState from '../components/ErrorState';
import ContextPanel from '../components/ContextPanel';
import StatCard from '../components/StatCard';

const SECTIONS = [
  { id: 'progress', label: 'Progress' },
  { id: 'summary', label: 'Summary' },
];

export default function ScanProgress() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { events, status } = useScanStream(id);
  const [viewResultsHovered, setViewResultsHovered] = useState(false);

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
              onMouseEnter={() => setViewResultsHovered(true)}
              onMouseLeave={() => setViewResultsHovered(false)}
              style={{
                border: '1px solid var(--accent)',
                borderRadius: 'var(--radius)',
                padding: '6px 14px',
                fontSize: '13px',
                color: 'var(--accent)',
                background: viewResultsHovered ? 'var(--success-bg)' : 'transparent',
                cursor: 'pointer',
                fontFamily: 'var(--font-sans)',
                transition: 'background 0.1s',
              }}
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
