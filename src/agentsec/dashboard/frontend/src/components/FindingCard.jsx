import { useState } from 'react';
import { SeverityBadge, StatusBadge } from './SeverityBadge';
import FindingDetail from './FindingDetail';

export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-slate-700/30 transition-colors text-left"
      >
        <div className="flex items-center gap-3">
          <StatusBadge status={finding.status} />
          <SeverityBadge severity={finding.severity} />
          <div>
            <span className="font-mono text-sm text-blue-400">{finding.probe_id}</span>
            <span className="text-sm text-slate-400 ml-2">{finding.probe_name}</span>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {finding.duration_ms != null && (
            <span className="text-xs text-slate-500">{finding.duration_ms}ms</span>
          )}
          <span className="text-slate-500 text-sm">{expanded ? '▲' : '▼'}</span>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4">
          <p className="text-sm text-slate-400 mb-2">{finding.description}</p>
          <FindingDetail finding={finding} />
        </div>
      )}
    </div>
  );
}
