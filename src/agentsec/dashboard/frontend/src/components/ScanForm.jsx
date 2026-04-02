import { useState, useEffect } from 'react';
import { fetchTargets } from '../api';

const inputStyle = {
  width: '100%',
  background: 'var(--bg-surface)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius)',
  padding: '7px 10px',
  fontSize: '13px',
  color: 'var(--text-primary)',
  fontFamily: 'var(--font-sans)',
  outline: 'none',
  boxSizing: 'border-box',
};

const labelStyle = {
  display: 'block',
  fontSize: '11px',
  color: 'var(--text-muted)',
  marginBottom: '5px',
  fontFamily: 'var(--font-sans)',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
};

export default function ScanForm({ onSubmit, loading }) {
  const [targets, setTargets] = useState([]);
  const [submitHovered, setSubmitHovered] = useState(false);
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
    <form onSubmit={handleSubmit} style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '20px',
    }}>
      <h2 style={{
        fontSize: '13px',
        fontWeight: 600,
        color: 'var(--text-primary)',
        marginBottom: '16px',
        fontFamily: 'var(--font-sans)',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
      }}>
        New Scan
      </h2>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        <div>
          <label style={labelStyle}>Target</label>
          <select
            value={config.target}
            onChange={e => setConfig({ ...config, target: e.target.value })}
            style={inputStyle}
            onFocus={e => { e.target.style.borderColor = 'var(--accent)'; }}
            onBlur={e => { e.target.style.borderColor = 'var(--border)'; }}
          >
            {targets.map(t => (
              <option key={t.path} value={t.path}>{t.name}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap' }}>
          {[
            { key: 'vulnerable', label: 'Vulnerable mode' },
            { key: 'smart', label: 'Smart payloads' },
            { key: 'live', label: 'Live LLM' },
          ].map(({ key, label }) => (
            <label key={key} style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '13px',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              fontFamily: 'var(--font-sans)',
            }}>
              <input
                type="checkbox"
                checked={config[key]}
                onChange={e => setConfig({ ...config, [key]: e.target.checked })}
                style={{ accentColor: 'var(--accent)', cursor: 'pointer' }}
              />
              {label}
            </label>
          ))}
        </div>

        <div>
          <button
            type="submit"
            disabled={loading || !config.target}
            style={{
              border: '1px solid var(--accent)',
              borderRadius: 'var(--radius)',
              padding: '7px 16px',
              fontSize: '13px',
              color: 'var(--accent)',
              background: submitHovered && !loading && config.target ? 'var(--success-bg)' : 'transparent',
              cursor: loading || !config.target ? 'not-allowed' : 'pointer',
              fontFamily: 'var(--font-sans)',
              fontWeight: 500,
              opacity: loading || !config.target ? 0.4 : 1,
              transition: 'background 0.1s',
            }}
            onMouseEnter={() => setSubmitHovered(true)}
            onMouseLeave={() => setSubmitHovered(false)}
          >
            {loading ? 'Scanning...' : 'Start Scan'}
          </button>
        </div>
      </div>
    </form>
  );
}
