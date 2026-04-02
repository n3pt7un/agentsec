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
  const [sortBy, setSortBy] = useState('date'); // date | vulnerabilities | probes

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
    await deleteScan(scanId);
    setScans(prev => prev.filter(s => s.scan_id !== scanId));
  };

  // Sort
  const sorted = [...scans].sort((a, b) => {
    if (sortBy === 'vulnerabilities') return b.vulnerable_count - a.vulnerable_count;
    if (sortBy === 'probes') return b.total_probes - a.total_probes;
    return new Date(b.started_at) - new Date(a.started_at);
  });

  if (error) return <ErrorState message={error} onRetry={loadScans} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Scan History</h1>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">Sort:</span>
          {['date', 'vulnerabilities', 'probes'].map(s => (
            <button
              key={s}
              onClick={() => setSortBy(s)}
              className={`px-2 py-1 rounded text-xs transition-colors ${
                sortBy === s
                  ? 'bg-slate-700 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="space-y-2">
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
        <div className="space-y-2">
          {sorted.map(scan => (
            <div key={scan.scan_id} className="relative group">
              <ScanCard scan={scan} />
              <button
                onClick={(e) => { e.preventDefault(); handleDelete(scan.scan_id); }}
                className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 text-xs text-red-400 hover:text-red-300 transition-opacity"
              >
                Delete
              </button>
            </div>
          ))}
        </div>
      )}

      {scans.length > 0 && (
        <div className="text-xs text-slate-500 text-center pt-4">
          {scans.length} scan{scans.length !== 1 ? 's' : ''} total
        </div>
      )}
    </div>
  );
}
