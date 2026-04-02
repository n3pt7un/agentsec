import { useState } from 'react';
import { useSettings } from '../hooks/useSettings';

const MODELS = [
  { value: 'anthropic/claude-sonnet-4-6', label: 'Claude Sonnet 4.6 (recommended)' },
  { value: 'anthropic/claude-opus-4-6', label: 'Claude Opus 4.6 (most capable)' },
  { value: 'anthropic/claude-haiku-4-5', label: 'Claude Haiku 4.5 (fastest)' },
  { value: 'openai/gpt-4o', label: 'GPT-4o' },
  { value: 'openai/gpt-4o-mini', label: 'GPT-4o Mini' },
  { value: 'google/gemini-2.0-flash-001', label: 'Gemini 2.0 Flash' },
];

export default function Settings() {
  const { settings, updateSettings } = useSettings();
  const [saved, setSaved] = useState(false);
  const [form, setForm] = useState(settings);

  const handleSave = (e) => {
    e.preventDefault();
    updateSettings(form);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="max-w-xl space-y-6">
      <h1 className="text-xl font-bold">Settings</h1>

      <form onSubmit={handleSave} className="bg-slate-800 rounded-lg border border-slate-700 p-6 space-y-5">
        <div>
          <label className="block text-sm text-slate-400 mb-1">LLM Model</label>
          <p className="text-xs text-slate-500 mb-2">
            Used for smart payload generation and LLM-based detection. Requires an OpenRouter API key.
          </p>
          <select
            value={form.llm_model}
            onChange={e => setForm({ ...form, llm_model: e.target.value })}
            className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-sm"
          >
            {MODELS.map(m => (
              <option key={m.value} value={m.value}>{m.label}</option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-sm text-slate-400 mb-1">OpenRouter API Key</label>
          <p className="text-xs text-slate-500 mb-2">
            Required for smart mode scans. Get one at{' '}
            <span className="text-blue-400">openrouter.ai</span>.
            Stored in your browser's localStorage only.
          </p>
          <input
            type="password"
            value={form.openrouter_api_key}
            onChange={e => setForm({ ...form, openrouter_api_key: e.target.value })}
            placeholder="sk-or-..."
            className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-sm font-mono"
          />
        </div>

        <div className="flex items-center gap-3">
          <button
            type="submit"
            className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded text-sm font-medium transition-colors"
          >
            Save Settings
          </button>
          {saved && (
            <span className="text-green-400 text-sm">&#10003; Saved</span>
          )}
        </div>
      </form>

      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 text-xs text-slate-400 space-y-1">
        <p className="font-medium text-slate-300">About API Keys</p>
        <p>Your API key is stored only in this browser's localStorage and never sent to any server other than OpenRouter (via the agentsec backend when running smart scans).</p>
        <p>Smart mode is off by default. Enable it per-scan in the scan form.</p>
      </div>
    </div>
  );
}
