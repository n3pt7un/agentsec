const CATEGORY_NAMES = {
  ASI01: 'Agent Goal Hijacking',
  ASI02: 'Tool Misuse & Exploitation',
  ASI03: 'Identity & Privilege Abuse',
  ASI04: 'Supply Chain Vulnerabilities',
  ASI05: 'Output & Impact Control Failures',
  ASI06: 'Memory & Context Manipulation',
  ASI07: 'Multi-Agent Orchestration',
  ASI08: 'Uncontrolled Autonomous Execution',
  ASI09: 'Human-Agent Trust Exploitation',
  ASI10: 'Rogue Agent Behavior',
};

const thStyle = {
  padding: '8px 14px',
  fontSize: '10px',
  fontFamily: 'var(--font-sans)',
  color: 'var(--text-muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
  fontWeight: 600,
  textAlign: 'left',
  borderBottom: '1px solid var(--border)',
};

export default function SummaryTable({ findings }) {
  const categories = {};
  for (const f of findings) {
    const cat = f.category;
    if (!categories[cat]) categories[cat] = { total: 0, vulnerable: 0, resistant: 0, other: 0 };
    categories[cat].total++;
    if (f.status === 'vulnerable' || f.status === 'partial') categories[cat].vulnerable++;
    else if (f.status === 'resistant') categories[cat].resistant++;
    else categories[cat].other++;
  }

  const sorted = Object.entries(categories).sort(([a], [b]) => a.localeCompare(b));

  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      overflow: 'hidden',
    }}>
      <table style={{ width: '100%', fontSize: '13px', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={thStyle}>Category</th>
            <th style={{ ...thStyle, textAlign: 'center' }}>Probes</th>
            <th style={{ ...thStyle, textAlign: 'center' }}>Vulnerable</th>
            <th style={{ ...thStyle, textAlign: 'center' }}>Resistant</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map(([cat, counts], i) => (
            <tr key={cat} style={{
              background: i % 2 === 0 ? 'var(--bg-surface)' : 'var(--bg-surface-raised)',
              borderBottom: '1px solid var(--border)',
            }}>
              <td style={{ padding: '8px 14px' }}>
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  color: 'var(--accent)',
                  marginRight: '8px',
                }}>
                  {cat}
                </span>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-sans)' }}>
                  {CATEGORY_NAMES[cat] || cat}
                </span>
              </td>
              <td style={{ padding: '8px 14px', textAlign: 'center', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                {counts.total}
              </td>
              <td style={{ padding: '8px 14px', textAlign: 'center', fontFamily: 'var(--font-mono)', fontWeight: counts.vulnerable > 0 ? 600 : 400 }}>
                <span style={{ color: counts.vulnerable > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
                  {counts.vulnerable}
                </span>
              </td>
              <td style={{ padding: '8px 14px', textAlign: 'center', fontFamily: 'var(--font-mono)' }}>
                <span style={{ color: counts.resistant > 0 ? 'var(--accent)' : 'var(--text-muted)' }}>
                  {counts.resistant}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
