import { useState, useEffect } from 'react';
import { fetchTargets, fetchProbes } from '../api';

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
    detection_mode: 'marker_then_llm',
  });

  const [allProbes, setAllProbes] = useState([]);
  const [selectedProbes, setSelectedProbes] = useState(new Set());
  const [probesPanelOpen, setProbesPanelOpen] = useState(false);
  const [expandedCats, setExpandedCats] = useState(new Set());

  useEffect(() => {
    fetchTargets().then(data => {
      setTargets(data.targets || []);
      if (data.targets?.length > 0) {
        setConfig(prev => ({ ...prev, target: data.targets[0].path }));
      }
    });
  }, []);

  useEffect(() => {
    fetchProbes().then(data => {
      const probes = data.probes || [];
      setAllProbes(probes);
      setSelectedProbes(new Set(probes.map(p => p.id)));
    });
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    const probes = selectedProbes.size === allProbes.length
      ? null
      : [...selectedProbes];
    onSubmit({ ...config, probes });
  };

  // Group probes by category for the tree
  const categoryGroups = allProbes.reduce((acc, probe) => {
    const cat = probe.category;
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(probe);
    return acc;
  }, {});
  const sortedCats = Object.keys(categoryGroups).sort();

  const noProbesSelected = allProbes.length > 0 && selectedProbes.size === 0;

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

        <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap', alignItems: 'center' }}>
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

          {config.smart && (
            <label style={{
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
                checked={config.detection_mode === 'llm_only'}
                onChange={e => setConfig({
                  ...config,
                  detection_mode: e.target.checked ? 'llm_only' : 'marker_then_llm',
                })}
                style={{ accentColor: 'var(--accent)', cursor: 'pointer' }}
              />
              LLM-only detection
            </label>
          )}
        </div>

        {/* Probe selector */}
        {allProbes.length > 0 && (
          <div>
            {/* Toggle row */}
            <div
              onClick={() => setProbesPanelOpen(o => !o)}
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                borderRadius: probesPanelOpen
                  ? 'var(--radius) var(--radius) 0 0'
                  : 'var(--radius)',
                padding: '7px 12px',
                fontSize: '13px',
                color: 'var(--text-secondary)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                cursor: 'pointer',
                userSelect: 'none',
                fontFamily: 'var(--font-sans)',
              }}
            >
              <span>Probe selection</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '12px',
                  color: noProbesSelected
                    ? 'var(--danger)'
                    : selectedProbes.size === allProbes.length
                      ? 'var(--accent)'
                      : 'var(--text-muted)',
                }}>
                  {selectedProbes.size} / {allProbes.length} probes
                </span>
                <span style={{
                  fontSize: '11px',
                  color: 'var(--accent)',
                  display: 'inline-block',
                  transform: probesPanelOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                  transition: 'transform 0.15s',
                }}>▾</span>
              </span>
            </div>

            {/* Expandable panel */}
            {probesPanelOpen && (
              <div style={{
                border: '1px solid var(--border)',
                borderTop: 'none',
                borderRadius: '0 0 var(--radius) var(--radius)',
                background: 'var(--bg-elevated, var(--bg-surface))',
                maxHeight: '260px',
                overflowY: 'auto',
              }}>
                {/* Select all / none */}
                <div style={{
                  padding: '6px 12px',
                  borderBottom: '1px solid var(--border)',
                  display: 'flex',
                  gap: '12px',
                  fontSize: '11px',
                }}>
                  <button
                    type="button"
                    onClick={() => setSelectedProbes(new Set(allProbes.map(p => p.id)))}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--accent)',
                      cursor: 'pointer',
                      padding: 0,
                      fontSize: '11px',
                      fontFamily: 'var(--font-sans)',
                    }}
                  >
                    Select all
                  </button>
                  <button
                    type="button"
                    onClick={() => setSelectedProbes(new Set())}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--accent)',
                      cursor: 'pointer',
                      padding: 0,
                      fontSize: '11px',
                      fontFamily: 'var(--font-sans)',
                    }}
                  >
                    Select none
                  </button>
                </div>

                {/* Category rows */}
                {sortedCats.map(cat => {
                  const catProbes = categoryGroups[cat];
                  const selectedInCat = catProbes.filter(p => selectedProbes.has(p.id)).length;
                  const allInCat = selectedInCat === catProbes.length;
                  const someInCat = selectedInCat > 0 && !allInCat;
                  const isExpanded = expandedCats.has(cat);

                  const toggleCat = (checked) => {
                    setSelectedProbes(prev => {
                      const next = new Set(prev);
                      catProbes.forEach(p => checked ? next.add(p.id) : next.delete(p.id));
                      return next;
                    });
                  };

                  const toggleExpand = () => {
                    setExpandedCats(prev => {
                      const next = new Set(prev);
                      next.has(cat) ? next.delete(cat) : next.add(cat);
                      return next;
                    });
                  };

                  return (
                    <div key={cat} style={{ borderBottom: '1px solid var(--border)' }}>
                      {/* Category row */}
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        padding: '6px 12px',
                        gap: '8px',
                        fontSize: '12px',
                        fontFamily: 'var(--font-sans)',
                      }}>
                        <input
                          type="checkbox"
                          checked={allInCat}
                          ref={el => { if (el) el.indeterminate = someInCat; }}
                          onChange={e => { e.stopPropagation(); toggleCat(e.target.checked); }}
                          onClick={e => e.stopPropagation()}
                          style={{ accentColor: 'var(--accent)', cursor: 'pointer', flexShrink: 0 }}
                        />
                        <span
                          onClick={toggleExpand}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px',
                            flex: 1,
                            cursor: 'pointer',
                          }}
                        >
                          <span style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '11px',
                            color: 'var(--accent)',
                            minWidth: '44px',
                          }}>
                            {cat}
                          </span>
                          <span style={{ color: 'var(--text-secondary)', flex: 1 }}>
                            {catProbes[0]?.name?.split(' ')[0] || cat}
                          </span>
                          <span style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '11px',
                            color: 'var(--text-muted)',
                          }}>
                            {selectedInCat}/{catProbes.length}
                          </span>
                          <span style={{
                            fontSize: '10px',
                            color: 'var(--text-muted)',
                            transform: isExpanded ? 'rotate(0deg)' : 'rotate(-90deg)',
                            transition: 'transform 0.15s',
                            display: 'inline-block',
                          }}>▾</span>
                        </span>
                      </div>

                      {/* Probe children */}
                      {isExpanded && catProbes.map(probe => (
                        <label
                          key={probe.id}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px',
                            padding: '5px 12px 5px 32px',
                            background: 'var(--bg-surface)',
                            fontSize: '11px',
                            cursor: 'pointer',
                            borderTop: '1px solid var(--border)',
                            fontFamily: 'var(--font-sans)',
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={selectedProbes.has(probe.id)}
                            onChange={e => {
                              setSelectedProbes(prev => {
                                const next = new Set(prev);
                                e.target.checked ? next.add(probe.id) : next.delete(probe.id);
                                return next;
                              });
                            }}
                            style={{ accentColor: 'var(--accent)', cursor: 'pointer', flexShrink: 0 }}
                          />
                          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                            {probe.id}
                          </span>
                        </label>
                      ))}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        <div>
          <button
            type="submit"
            disabled={loading || !config.target || noProbesSelected}
            style={{
              border: '1px solid var(--accent)',
              borderRadius: 'var(--radius)',
              padding: '7px 16px',
              fontSize: '13px',
              color: 'var(--accent)',
              background: submitHovered && !loading && config.target && !noProbesSelected
                ? 'var(--success-bg)'
                : 'transparent',
              cursor: loading || !config.target || noProbesSelected ? 'not-allowed' : 'pointer',
              fontFamily: 'var(--font-sans)',
              fontWeight: 500,
              opacity: loading || !config.target || noProbesSelected ? 0.4 : 1,
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
