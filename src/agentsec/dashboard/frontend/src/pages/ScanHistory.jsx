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
