import { useState, useEffect } from 'react';
import { IconCheck } from '@tabler/icons-react';
import { useSettings } from '../hooks/useSettings';

const MODELS = [
  { value: 'anthropic/claude-sonnet-4-6', label: 'Claude Sonnet 4.6 (recommended)' },
  { value: 'anthropic/claude-opus-4-6', label: 'Claude Opus 4.6 (most capable)' },
  { value: 'anthropic/claude-haiku-4-5', label: 'Claude Haiku 4.5 (fastest)' },
  { value: 'openai/gpt-4o', label: 'GPT-4o' },
  { value: 'openai/gpt-4o-mini', label: 'GPT-4o Mini' },
  { value: 'google/gemini-2.0-flash-001', label: 'Gemini 2.0 Flash' },
];

const TARGET_MODELS = [
  { value: 'openai/gpt-4.1-nano', label: 'GPT-4.1 Nano (fast, cheap — good default)' },
  { value: 'openai/gpt-4o-mini', label: 'GPT-4o Mini' },
  { value: 'openai/gpt-4o', label: 'GPT-4o' },
  { value: 'anthropic/claude-haiku-4-5', label: 'Claude Haiku 4.5' },
  { value: 'anthropic/claude-sonnet-4-6', label: 'Claude Sonnet 4.6' },
  { value: 'google/gemini-2.0-flash-001', label: 'Gemini 2.0 Flash' },
  { value: 'meta-llama/llama-3.3-70b-instruct', label: 'Llama 3.3 70B' },
];

const fieldLabel = {
  fontSize: '11px',
  color: 'var(--text-muted)',
  fontFamily: 'var(--font-sans)',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  display: 'block',
  marginBottom: '5px',
};

const fieldHint = {
  fontSize: '11px',
  color: 'var(--text-muted)',
  fontFamily: 'var(--font-sans)',
  marginBottom: '6px',
  lineHeight: 1.5,
};

const inputBase = {
  width: '100%',
  background: 'var(--bg-page)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius)',
  padding: '7px 10px',
  fontSize: '13px',
  color: 'var(--text-primary)',
  outline: 'none',
  boxSizing: 'border-box',
};

export default function Settings() {
  const { settings, updateSettings } = useSettings();
  const [saved, setSaved] = useState(false);
  const [saveHovered, setSaveHovered] = useState(false);
  const [form, setForm] = useState(settings);

  useEffect(() => { setForm(settings); }, [settings]);

  const handleSave = (e) => {
    e.preventDefault();
    updateSettings(form);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div style={{ maxWidth: '520px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <h1 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-sans)' }}>
        Settings
      </h1>

      <form onSubmit={handleSave} style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '18px',
      }}>
        <div>
          <label style={fieldLabel} htmlFor="settings-llm-model">LLM Model</label>
          <p style={fieldHint}>Used for smart payload generation. Requires an OpenRouter API key.</p>
          <select
            id="settings-llm-model"
            value={form.llm_model}
            onChange={e => setForm({ ...form, llm_model: e.target.value })}
            style={{ ...inputBase, fontFamily: 'var(--font-sans)' }}
            onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
            onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
          >
            {MODELS.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
          </select>
        </div>

        <div>
          <label style={fieldLabel} htmlFor="settings-target-model">Target Model</label>
          <p style={fieldHint}>The LLM running inside your agent under test. Only used when Live LLM is enabled on a scan.</p>
          <select
            id="settings-target-model"
            value={form.target_model}
            onChange={e => setForm({ ...form, target_model: e.target.value })}
            style={{ ...inputBase, fontFamily: 'var(--font-sans)' }}
            onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
            onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
          >
            {TARGET_MODELS.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
          </select>
        </div>

        <div>
          <label style={fieldLabel} htmlFor="settings-api-key">OpenRouter API Key</label>
          <p style={fieldHint}>
            Required for smart mode scans. Get one at{' '}
            <a href="https://openrouter.ai" target="_blank" rel="noopener noreferrer"
               style={{ color: 'var(--accent)', fontFamily: 'var(--font-sans)' }}>
              openrouter.ai
            </a>.
            Stored in your browser only.
          </p>
          <input
            id="settings-api-key"
            type="password"
            value={form.openrouter_api_key}
            onChange={e => setForm({ ...form, openrouter_api_key: e.target.value })}
            placeholder="sk-or-..."
            style={{ ...inputBase, fontFamily: 'var(--font-mono)' }}
            onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
            onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            type="submit"
            onMouseEnter={() => setSaveHovered(true)}
            onMouseLeave={() => setSaveHovered(false)}
            style={{
              border: '1px solid var(--accent)',
              borderRadius: 'var(--radius)',
              padding: '7px 16px',
              fontSize: '13px',
              color: 'var(--accent)',
              background: saveHovered ? 'var(--success-bg)' : 'transparent',
              cursor: 'pointer',
              fontFamily: 'var(--font-sans)',
              fontWeight: 500,
              transition: 'background 0.1s',
            }}
          >
            Save Settings
          </button>
          {saved && (
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '13px', color: 'var(--accent)', fontFamily: 'var(--font-sans)' }}>
              <IconCheck size={14} stroke={2} /> Saved
            </span>
          )}
        </div>
      </form>

      <div style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: '14px',
        fontSize: '11px',
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-sans)',
        display: 'flex',
        flexDirection: 'column',
        gap: '5px',
        lineHeight: 1.6,
      }}>
        <p style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>About API Keys</p>
        <p>Your API key is stored only in this browser localStorage and never sent to any server other than OpenRouter (via the agentsec backend when running smart scans).</p>
        <p>Smart mode is off by default. Enable it per-scan in the scan form.</p>
      </div>
    </div>
  );
}
