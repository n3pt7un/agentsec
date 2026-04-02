const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['vulnerable', 'resistant', 'partial', 'error', 'skipped'];

export default function FindingFilters({ findings, filters, onFilterChange }) {
  // Derive available categories from findings
  const categories = [...new Set(findings.map(f => f.category))].sort();

  const toggle = (key, value) => {
    const current = new Set(filters[key] || []);
    if (current.has(value)) current.delete(value);
    else current.add(value);
    onFilterChange({ ...filters, [key]: [...current] });
  };

  const isActive = (key, value) => {
    if (!filters[key] || filters[key].length === 0) return true;  // no filter = show all
    return filters[key].includes(value);
  };

  return (
    <div className="flex flex-wrap gap-4 items-center">
      <div className="flex items-center gap-1">
        <span className="text-xs text-slate-500 mr-1">Status:</span>
        {STATUSES.map(s => (
          <button
            key={s}
            onClick={() => toggle('statuses', s)}
            className={`px-2 py-0.5 rounded text-xs border transition-colors ${
              isActive('statuses', s)
                ? 'border-slate-500 text-slate-200 bg-slate-700'
                : 'border-slate-700 text-slate-600 bg-transparent'
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-1">
        <span className="text-xs text-slate-500 mr-1">Severity:</span>
        {SEVERITIES.map(s => (
          <button
            key={s}
            onClick={() => toggle('severities', s)}
            className={`px-2 py-0.5 rounded text-xs border transition-colors ${
              isActive('severities', s)
                ? 'border-slate-500 text-slate-200 bg-slate-700'
                : 'border-slate-700 text-slate-600 bg-transparent'
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      {categories.length > 1 && (
        <div className="flex items-center gap-1">
          <span className="text-xs text-slate-500 mr-1">Category:</span>
          {categories.map(c => (
            <button
              key={c}
              onClick={() => toggle('categories', c)}
              className={`px-2 py-0.5 rounded text-xs font-mono border transition-colors ${
                isActive('categories', c)
                  ? 'border-slate-500 text-slate-200 bg-slate-700'
                  : 'border-slate-700 text-slate-600 bg-transparent'
              }`}
            >
              {c}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
