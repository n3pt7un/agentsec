import { useState, useEffect } from 'react';
import { fetchTargets } from '../api';

export default function ScanForm({ onSubmit, loading }) {
  const [targets, setTargets] = useState([]);
  const [config, setConfig] = useState({
    target: '',
    adapter: 'langgraph',
    vulnerable: true,
    smart: false,
    live: false,
  });

  useEffect(() => {
    fetchTargets().then(data => {
      setTargets(data.targets || []);
      if (data.targets?.length > 0) {
        setConfig(prev => ({ ...prev, target: data.targets[0].path }));
      }
    });
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    onSubmit(config);
  };

  return (
    <form onSubmit={handleSubmit} className="bg-slate-800 rounded-lg border border-slate-700 p-6">
      <h2 className="text-lg font-semibold mb-4">New Scan</h2>

      <div className="space-y-4">
        <div>
          <label className="block text-sm text-slate-400 mb-1">Target</label>
          <select
            value={config.target}
            onChange={e => setConfig({ ...config, target: e.target.value })}
            className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-sm"
          >
            {targets.map(t => (
              <option key={t.path} value={t.path}>{t.name}</option>
            ))}
          </select>
        </div>

        <div className="flex gap-4 flex-wrap">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={config.vulnerable}
              onChange={e => setConfig({ ...config, vulnerable: e.target.checked })}
              className="rounded"
            />
            Vulnerable mode
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={config.smart}
              onChange={e => setConfig({ ...config, smart: e.target.checked })}
              className="rounded"
            />
            Smart payloads
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={config.live}
              onChange={e => setConfig({ ...config, live: e.target.checked })}
              className="rounded"
            />
            Live LLM
          </label>
        </div>

        <button
          type="submit"
          disabled={loading || !config.target}
          className="bg-blue-600 hover:bg-blue-500 disabled:bg-slate-600 px-4 py-2 rounded text-sm font-medium transition-colors"
        >
          {loading ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>
    </form>
  );
}
