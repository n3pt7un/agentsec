import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { fetchScan, deleteScan } from '../api';
import { SkeletonTable, SkeletonGraph } from '../components/LoadingSkeleton';
import ErrorState from '../components/ErrorState';
import SummaryTable from '../components/SummaryTable';
import AgentGraph from '../components/AgentGraph';
import FindingCard from '../components/FindingCard';
import FindingFilters from '../components/FindingFilters';

export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);
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
    try {
      await deleteScan(id);
      navigate('/scans');
    } catch (err) {
      setError(err.message || 'Failed to delete scan');
    }
  };

  if (error) {
    return (
      <div className="space-y-4">
        <ErrorState message={error} />
        <div className="text-center">
          <button
            onClick={() => navigate('/scans')}
            className="text-sm text-blue-400 hover:underline"
          >
            ← Back to scans
          </button>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="space-y-6">
        <div className="h-10 bg-slate-800 rounded w-1/3 animate-pulse" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="bg-slate-800 rounded-lg border border-slate-700 p-4 animate-pulse h-20" />
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
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">{scan.target || 'Scan Result'}</h1>
          <p className="text-sm text-slate-500">
            {new Date(scan.started_at).toLocaleString()} · {scan.duration_ms}ms · {scan.total_probes} probes
          </p>
        </div>
        <div className="flex items-center gap-4">
          <button
            onClick={handleDelete}
            className="text-xs text-red-400 hover:text-red-300"
          >
            Delete scan
          </button>
          <Link to="/scans" className="text-sm text-blue-400 hover:underline">← All scans</Link>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-4">
        <Stat label="Total" value={scan.total_probes} />
        <Stat label="Vulnerable" value={scan.vulnerable_count} color="text-red-400" />
        <Stat label="Resistant" value={scan.resistant_count} color="text-green-400" />
        <Stat label="Errors" value={scan.error_count} color="text-red-600" />
      </div>

      {/* Agent graph */}
      {scan.agents_discovered?.length > 0 && (
        <AgentGraph agents={scan.agents_discovered} />
      )}

      {/* Summary table */}
      {findings.length > 0 && <SummaryTable findings={findings} />}

      {/* Findings */}
      {findings.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Findings</h2>
            <span className="text-sm text-slate-500">
              Showing {filtered.length} of {findings.length}
            </span>
          </div>

          <FindingFilters findings={findings} filters={filters} onFilterChange={setFilters} />

          <div className="space-y-2">
            {filtered.map((f, i) => (
              <FindingCard key={`${f.probe_id}-${i}`} finding={f} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, color = 'text-slate-100' }) {
  return (
    <div className="bg-slate-800 rounded-lg border border-slate-700 p-4 text-center">
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-slate-400">{label}</div>
    </div>
  );
}
