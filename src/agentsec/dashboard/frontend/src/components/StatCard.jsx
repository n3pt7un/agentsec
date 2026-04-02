export default function StatCard({ label, value, color }) {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '14px',
      textAlign: 'center',
    }}>
      <div style={{
        fontSize: '22px',
        fontWeight: 600,
        fontFamily: 'var(--font-mono)',
        color: color || 'var(--text-primary)',
        marginBottom: '4px',
      }}>
        {value}
      </div>
      <div style={{
        fontSize: '10px',
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-sans)',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
      }}>
        {label}
      </div>
    </div>
  );
}
