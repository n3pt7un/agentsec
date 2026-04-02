import { Link } from 'react-router-dom';

export default function ScanCard({ scan }) {
  return (
    <Link
      to={`/scans/${scan.scan_id}`}
      className="block bg-slate-800 border border-slate-700 rounded-lg p-4 hover:border-slate-600 transition-colors"
    >
      <div className="flex items-center justify-between mb-2">
        <span className="font-medium text-sm">{scan.target}</span>
        <span className="text-xs text-slate-500">
          {new Date(scan.started_at).toLocaleString()}
        </span>
      </div>
      <div className="flex gap-4 text-xs">
        <span className="text-slate-400">{scan.total_probes} probes</span>
        {scan.vulnerable_count > 0 && (
          <span className="text-red-400">{scan.vulnerable_count} vulnerable</span>
        )}
        {scan.resistant_count > 0 && (
          <span className="text-green-400">{scan.resistant_count} resistant</span>
        )}
        {scan.error_count > 0 && (
          <span className="text-red-600">{scan.error_count} errors</span>
        )}
        <span className="text-slate-500">{scan.duration_ms}ms</span>
      </div>
    </Link>
  );
}
