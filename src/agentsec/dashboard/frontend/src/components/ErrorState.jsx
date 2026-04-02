import { IconAlertCircle } from '@tabler/icons-react';

export default function ErrorState({ message, onRetry }) {
  return (
    <div style={{
      background: 'var(--danger-bg)',
      border: '1px solid var(--border-red)',
      borderRadius: 'var(--radius)',
      padding: '24px',
      textAlign: 'center',
    }}>
      <div style={{ color: 'var(--danger)', marginBottom: '12px', display: 'flex', justifyContent: 'center' }}>
        <IconAlertCircle size={32} stroke={1.25} />
      </div>
      <p style={{
        color: 'var(--danger)',
        marginBottom: onRetry ? '16px' : 0,
        fontSize: '13px',
        fontFamily: 'var(--font-sans)',
      }}>
        {message || 'Something went wrong'}
      </p>
      {onRetry && (
        <button
          onClick={onRetry}
          style={{
            border: '1px solid var(--danger)',
            borderRadius: 'var(--radius)',
            padding: '6px 14px',
            fontSize: '13px',
            color: 'var(--danger)',
            background: 'transparent',
            cursor: 'pointer',
            fontFamily: 'var(--font-sans)',
          }}
        >
          Try Again
        </button>
      )}
    </div>
  );
}
