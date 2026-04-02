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

export default function SummaryTable({ findings }) {
  // Group by category
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
    <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-700 text-left text-slate-400">
            <th className="px-4 py-3">Category</th>
            <th className="px-4 py-3 text-center">Probes</th>
            <th className="px-4 py-3 text-center">Vulnerable</th>
            <th className="px-4 py-3 text-center">Resistant</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map(([cat, counts]) => (
            <tr key={cat} className="border-b border-slate-700/50 hover:bg-slate-700/30">
              <td className="px-4 py-2">
                <span className="font-mono text-xs text-blue-400 mr-2">{cat}</span>
                <span className="text-slate-300">{CATEGORY_NAMES[cat] || cat}</span>
              </td>
              <td className="px-4 py-2 text-center text-slate-300">{counts.total}</td>
              <td className="px-4 py-2 text-center">
                {counts.vulnerable > 0
                  ? <span className="text-red-400 font-bold">{counts.vulnerable}</span>
                  : <span className="text-slate-500">0</span>}
              </td>
              <td className="px-4 py-2 text-center">
                {counts.resistant > 0
                  ? <span className="text-green-400">{counts.resistant}</span>
                  : <span className="text-slate-500">0</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
