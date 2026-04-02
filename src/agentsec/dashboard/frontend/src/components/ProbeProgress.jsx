import {
  IconRadar,
  IconCheck,
  IconX,
  IconAdjustments,
  IconPlayerSkipForward,
} from '@tabler/icons-react';

const STATUS_CONFIG = {
  started:    { Icon: IconRadar, color: 'var(--accent)', spin: true },
  vulnerable: { Icon: IconX, color: 'var(--danger)', spin: false },
  resistant:  { Icon: IconCheck, color: 'var(--accent)', spin: false },
  partial:    { Icon: IconAdjustments, color: 'var(--warning)', spin: false },
  error:      { Icon: IconX, color: 'var(--danger)', spin: false },
  skipped:    { Icon: IconPlayerSkipForward, color: 'var(--text-muted)', spin: false },
};

function ProbeIcon({ status }) {
  const { Icon, color, spin } = STATUS_CONFIG[status] ?? STATUS_CONFIG.started;
  return (
    <span style={{
      color,
      display: 'flex',
      alignItems: 'center',
      ...(spin ? { animation: 'spin 1.2s linear infinite' } : {}),
    }}>
      <Icon size={14} stroke={1.5} />
    </span>
  );
}

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
    <>
      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {Object.values(probes).map(probe => (
          <div
            key={probe.probe_id}
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: '8px 14px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ProbeIcon status={probe.status ?? 'started'} />
              <div>
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '12px',
                  color: 'var(--accent)',
                }}>
                  {probe.probe_id}
                </span>
                {probe.probe_name && (
                  <span style={{
                    fontSize: '11px',
                    color: 'var(--text-muted)',
                    marginLeft: '8px',
                    fontFamily: 'var(--font-sans)',
                  }}>
                    {probe.probe_name}
                  </span>
                )}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              {probe.status && (
                <span style={{
                  fontSize: '10px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  color: (STATUS_CONFIG[probe.status] ?? STATUS_CONFIG.started).color,
                }}>
                  {probe.status}
                </span>
              )}
              {probe.duration_ms != null && (
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  {probe.duration_ms}ms
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
