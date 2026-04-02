const SEVERITY_STYLES = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
};

const STATUS_STYLES = {
  vulnerable: 'bg-red-500/20 text-red-400 border-red-500/30',
  resistant: 'bg-green-500/20 text-green-400 border-green-500/30',
  partial: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  error: 'bg-red-800/20 text-red-600 border-red-800/30',
  skipped: 'bg-slate-500/20 text-slate-500 border-slate-500/30',
};

export function SeverityBadge({ severity }) {
  const style = SEVERITY_STYLES[severity] || SEVERITY_STYLES.info;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase border ${style}`}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }) {
  const style = STATUS_STYLES[status] || STATUS_STYLES.skipped;
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase border ${style}`}>
      {status}
    </span>
  );
}
