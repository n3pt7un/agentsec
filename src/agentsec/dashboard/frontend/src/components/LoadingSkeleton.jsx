const shimmer = {
  background: 'var(--bg-surface-raised)',
  borderRadius: 'var(--radius)',
  animation: 'pulse 1.5s ease-in-out infinite',
};

export function SkeletonCard() {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '14px 16px',
    }}>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }`}</style>
      <div style={{ ...shimmer, height: '13px', width: '60%', marginBottom: '10px' }} />
      <div style={{ ...shimmer, height: '11px', width: '35%' }} />
    </div>
  );
}

export function SkeletonTable({ rows = 4 }) {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      overflow: 'hidden',
    }}>
      <div style={{ height: '36px', background: 'var(--bg-surface-raised)', borderBottom: '1px solid var(--border)' }} />
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} style={{
          height: '36px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          padding: '0 14px',
          gap: '16px',
        }}>
          <div style={{ ...shimmer, height: '11px', width: '25%' }} />
          <div style={{ ...shimmer, height: '11px', width: '15%' }} />
          <div style={{ ...shimmer, height: '11px', width: '12%' }} />
        </div>
      ))}
    </div>
  );
}

export function SkeletonGraph() {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '16px',
      height: '400px',
    }}>
      <div style={{ ...shimmer, height: '12px', width: '20%', marginBottom: '16px' }} />
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        height: 'calc(100% - 40px)',
        color: 'var(--text-muted)',
        fontSize: '12px',
        fontFamily: 'var(--font-sans)',
      }}>
        Loading graph...
      </div>
    </div>
  );
}
