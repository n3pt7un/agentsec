import { useActiveSection } from '../hooks/useActiveSection';

export default function ContextPanel({ sections }) {
  const ids = sections.map(s => s.id);
  const activeId = useActiveSection(ids);

  return (
    <aside style={{
      width: '148px',
      flexShrink: 0,
      position: 'sticky',
      top: '56px',
      alignSelf: 'flex-start',
      paddingRight: '16px',
      borderRight: '1px solid var(--border)',
    }}>
      <nav style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
        {sections.map(s => (
          <a
            key={s.id}
            href={`#${s.id}`}
            style={{
              display: 'block',
              padding: '5px 0',
              fontSize: '11px',
              fontFamily: 'var(--font-sans)',
              color: activeId === s.id ? 'var(--accent)' : 'var(--text-muted)',
              textDecoration: 'none',
              letterSpacing: '0.02em',
              transition: 'color 0.1s',
            }}
          >
            {s.label}
          </a>
        ))}
      </nav>
    </aside>
  );
}
