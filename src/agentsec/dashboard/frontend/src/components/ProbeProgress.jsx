const STATUS_COLORS = {
  started: 'text-blue-400',
  vulnerable: 'text-red-400',
  resistant: 'text-green-400',
  partial: 'text-yellow-400',
  error: 'text-red-600',
  skipped: 'text-slate-500',
};

const STATUS_ICONS = {
  started: '⏳',
  vulnerable: '🔴',
  resistant: '✅',
  partial: '🟡',
  error: '❌',
  skipped: '⏭️',
};

export default function ProbeProgress({ events }) {
  const probes = {};
  for (const event of events) {
    if (event.type === 'scan_complete' || event.type === 'error') continue;
    const id = event.probe_id;
    if (!probes[id]) probes[id] = { probe_id: id, probe_name: event.probe_name };
    if (event.type === 'completed') {
      probes[id].status = event.status;
      probes[id].severity = event.severity;
      probes[id].duration_ms = event.duration_ms;
    }
  }

  return (
    <div className="space-y-2">
      {Object.values(probes).map(probe => (
        <div
          key={probe.probe_id}
          className="bg-slate-800 border border-slate-700 rounded px-4 py-2 flex items-center justify-between"
        >
          <div className="flex items-center gap-3">
            <span>{STATUS_ICONS[probe.status || 'started']}</span>
            <div>
              <span className="text-sm font-medium">{probe.probe_id}</span>
              <span className="text-xs text-slate-500 ml-2">{probe.probe_name}</span>
            </div>
          </div>
          <div className="flex items-center gap-3 text-sm">
            {probe.severity && (
              <span className={`uppercase text-xs font-bold ${STATUS_COLORS[probe.status]}`}>
                {probe.status}
              </span>
            )}
            {probe.duration_ms != null && (
              <span className="text-slate-500 text-xs">{probe.duration_ms}ms</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
