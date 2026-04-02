import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchScan } from '../api';
import SummaryTable from '../components/SummaryTable';
import AgentGraph from '../components/AgentGraph';
import FindingCard from '../components/FindingCard';
import FindingFilters from '../components/FindingFilters';

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [filters, setFilters] = useState({ statuses: [], severities: [], categories: [] });

  useEffect(() => {
    fetchScan(id).then(setScan);
  }, [id]);

  if (!scan) return <div className="text-slate-400">Loading scan...</div>;

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
        <Link to="/scans" className="text-sm text-blue-400 hover:underline">← All scans</Link>
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
