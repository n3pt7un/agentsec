import { Link } from 'react-router-dom';
import { IconInbox } from '@tabler/icons-react';

export default function EmptyState({ title, description, actionLabel, actionTo }) {
  return (
    <div style={{ textAlign: 'center', padding: '48px 24px' }}>
      <div style={{ color: 'var(--text-muted)', marginBottom: '16px', display: 'flex', justifyContent: 'center' }}>
        <IconInbox size={36} stroke={1} />
      </div>
      <h3 style={{
        fontSize: '15px',
        fontWeight: 600,
        color: 'var(--text-secondary)',
        marginBottom: '8px',
        fontFamily: 'var(--font-sans)',
      }}>
        {title}
      </h3>
      <p style={{
        fontSize: '13px',
        color: 'var(--text-muted)',
        marginBottom: '20px',
        fontFamily: 'var(--font-sans)',
      }}>
        {description}
      </p>
      {actionTo && (
        <Link
          to={actionTo}
          style={{
            display: 'inline-block',
            border: '1px solid var(--accent)',
            borderRadius: 'var(--radius)',
            padding: '6px 14px',
            fontSize: '13px',
            color: 'var(--accent)',
            textDecoration: 'none',
            fontFamily: 'var(--font-sans)',
          }}
        >
          {actionLabel || 'Get Started'}
        </Link>
      )}
    </div>
  );
}
