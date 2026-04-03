import { useState, useEffect, useCallback } from 'react';
import ScanCard from '../components/ScanCard';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';
import { SkeletonCard } from '../components/LoadingSkeleton';
import { fetchScans, deleteScan, exportScans } from '../api';

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deleteError, setDeleteError] = useState(null);
  const [sortBy, setSortBy] = useState('date');
  const [hoveredId, setHoveredId] = useState(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);
  const [selectedIds, setSelectedIds] = useState(new Set());

  const toggleSelect = (scanId, e) => {
    e.preventDefault();
    e.stopPropagation();
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(scanId)) {
        next.delete(scanId);
      } else {
        next.add(scanId);
      }
      return next;
    });
  };

  const clearSelection = () => setSelectedIds(new Set());

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
    try {
      await deleteScan(scanId);
      setScans(prev => prev.filter(s => s.scan_id !== scanId));
      setConfirmDeleteId(null);
    } catch (err) {
      setDeleteError(err.message || 'Failed to delete scan');
      setConfirmDeleteId(null);
    }
  };

  const sorted = [...scans].sort((a, b) => {
    if (sortBy === 'vulnerabilities') return b.vulnerable_count - a.vulnerable_count;
    if (sortBy === 'probes') return b.total_probes - a.total_probes;
    return new Date(b.started_at || 0) - new Date(a.started_at || 0);
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
        <>
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
            {deleteError}
          </div>
        )}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {sorted.map(scan => (
            <div
              key={scan.scan_id}
              style={{ position: 'relative' }}
              onMouseEnter={() => setHoveredId(scan.scan_id)}
              onMouseLeave={() => setHoveredId(null)}
            >
              <ScanCard scan={scan} />

              {/* Checkbox — left side, appears on hover or when selection is active */}
              <input
                type="checkbox"
                checked={selectedIds.has(scan.scan_id)}
                onChange={(e) => toggleSelect(scan.scan_id, e)}
                onClick={(e) => e.stopPropagation()}
                style={{
                  position: 'absolute',
                  left: '6px',
                  top: '6px',
                  cursor: 'pointer',
                  opacity: hoveredId === scan.scan_id || selectedIds.size > 0 ? 1 : 0,
                  transition: 'opacity 0.1s',
                  pointerEvents: hoveredId === scan.scan_id || selectedIds.size > 0 ? 'auto' : 'none',
                  accentColor: 'var(--accent)',
                  width: '14px',
                  height: '14px',
                }}
              />

              {confirmDeleteId === scan.scan_id ? (
                <span style={{ position: 'absolute', bottom: '10px', right: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Delete?</span>
                  <button
                    onClick={(e) => { e.preventDefault(); handleDelete(scan.scan_id); }}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '11px', color: 'var(--danger)', fontFamily: 'var(--font-sans)', fontWeight: 600 }}
                  >
                    Yes
                  </button>
                  <button
                    onClick={(e) => { e.preventDefault(); setConfirmDeleteId(null); }}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}
                  >
                    No
                  </button>
                </span>
              ) : (
                <button
                  onClick={(e) => { e.preventDefault(); setConfirmDeleteId(scan.scan_id); }}
                  style={{
                    position: 'absolute',
                    bottom: '10px',
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
              )}
            </div>
          ))}
        </div>
        </>
      )}

      {scans.length > 0 && (
        <div style={{ fontSize: '11px', color: 'var(--text-muted)', textAlign: 'center', paddingTop: '8px', fontFamily: 'var(--font-mono)' }}>
          {scans.length} scan{scans.length !== 1 ? 's' : ''}
        </div>
      )}

      {selectedIds.size > 0 && (
        <div style={{
          position: 'fixed',
          bottom: '24px',
          left: '50%',
          transform: 'translateX(-50%)',
          background: 'var(--bg-surface-raised)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          boxShadow: '0 4px 16px rgba(0,0,0,0.3)',
          padding: '10px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          zIndex: 100,
          whiteSpace: 'nowrap',
        }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>
            {selectedIds.size} selected
          </span>
          <button
            onClick={() => exportScans([...selectedIds], 'md')}
            style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '12px', color: 'var(--accent)', fontFamily: 'var(--font-sans)' }}
          >
            Export MD
          </button>
          <button
            onClick={() => exportScans([...selectedIds], 'json')}
            style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '12px', color: 'var(--accent)', fontFamily: 'var(--font-sans)' }}
          >
            Export JSON
          </button>
          <span style={{ width: '1px', height: '16px', background: 'var(--border)' }} />
          <button
            onClick={() => exportScans('all', 'md')}
            style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}
          >
            Export all MD
          </button>
          <button
            onClick={() => exportScans('all', 'json')}
            style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}
          >
            Export all JSON
          </button>
          <button
            onClick={clearSelection}
            style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)', marginLeft: '4px' }}
            title="Clear selection"
          >
            ✕
          </button>
        </div>
      )}
    </div>
  );
}
