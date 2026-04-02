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
  const [deleteHovered, setDeleteHovered] = useState(false);
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
        <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }`}</style>
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

  // Apply filters
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
              {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'} · {scan.duration_ms}ms · {scan.total_probes} probes
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <button
              onClick={handleDelete}
              onMouseEnter={() => setDeleteHovered(true)}
              onMouseLeave={() => setDeleteHovered(false)}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                fontSize: '12px',
                color: 'var(--danger)',
                fontFamily: 'var(--font-sans)',
                opacity: deleteHovered ? 1 : 0.7,
                transition: 'opacity 0.1s',
              }}
            >
              Delete
            </button>
            <Link to="/scans" style={{ fontSize: '12px', color: 'var(--accent)', fontFamily: 'var(--font-sans)', textDecoration: 'none' }}>
              ← All scans
            </Link>
          </div>
        </div>

        {/* Delete error (shown inline, does not replace scan view) */}
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
