const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['vulnerable', 'resistant', 'partial', 'error', 'skipped'];

function pillStyle(active) {
  return {
    padding: '2px 8px',
    borderRadius: 'var(--radius)',
    fontSize: '11px',
    fontFamily: 'var(--font-mono)',
    border: `1px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
    color: active ? 'var(--accent)' : 'var(--text-muted)',
    background: active ? 'var(--success-bg)' : 'transparent',
    cursor: 'pointer',
    transition: 'border-color 0.1s, color 0.1s',
  };
}

export default function FindingFilters({ findings, filters, onFilterChange }) {
  const categories = [...new Set(findings.map(f => f.category))].sort();

  const toggle = (key, value) => {
    const current = new Set(filters[key] || []);
    if (current.has(value)) current.delete(value);
    else current.add(value);
    onFilterChange({ ...filters, [key]: [...current] });
  };

  const isActive = (key, value) => {
    if (!filters[key] || filters[key].length === 0) return true;
    return filters[key].includes(value);
  };

  const groupLabel = {
    fontSize: '11px',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-sans)',
    marginRight: '6px',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
  };

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
        <span style={groupLabel}>Status</span>
        {STATUSES.map(s => (
          <button key={s} onClick={() => toggle('statuses', s)} style={pillStyle(isActive('statuses', s))}>
            {s}
          </button>
        ))}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
        <span style={groupLabel}>Severity</span>
        {SEVERITIES.map(s => (
          <button key={s} onClick={() => toggle('severities', s)} style={pillStyle(isActive('severities', s))}>
            {s}
          </button>
        ))}
      </div>

      {categories.length > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
          <span style={groupLabel}>Category</span>
          {categories.map(c => (
            <button key={c} onClick={() => toggle('categories', c)} style={pillStyle(isActive('categories', c))}>
              {c}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
