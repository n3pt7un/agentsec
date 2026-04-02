import CodeBlock from './CodeBlock';

export default function FindingDetail({ finding }) {
  const { evidence, remediation } = finding;
  const isResistant = finding.status === 'resistant';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px', borderTop: '1px solid var(--border)' }}>
      {/* Evidence / Interaction Log */}
      {evidence && (
        <div>
          <h4 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', fontFamily: 'var(--font-sans)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {isResistant ? 'Interaction Log' : 'Evidence'}
          </h4>
          <div style={{
            background: 'var(--bg-page)',
            border: `1px solid ${isResistant ? 'var(--border-green)' : 'var(--border)'}`,
            borderRadius: 'var(--radius)',
            padding: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
            fontSize: '12px',
          }}>
            <div>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Attack input: </span>
              <code style={{ color: isResistant ? 'var(--text-secondary)' : 'var(--danger)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{evidence.attack_input}</code>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Target agent: </span>
              <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>{evidence.target_agent}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Response: </span>
              <code style={{ color: isResistant ? 'var(--accent)' : 'var(--warning)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{evidence.agent_response}</code>
            </div>
            {evidence.additional_context && (
              <div>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Context: </span>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-sans)' }}>{evidence.additional_context}</span>
              </div>
            )}
            {evidence.detection_method && (
              <div>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>Detection: </span>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-sans)' }}>{evidence.detection_method}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Blast radius — only for vulnerable/partial */}
      {!isResistant && finding.blast_radius && (
        <div style={{
          background: 'var(--danger-bg)',
          border: '1px solid var(--border-red)',
          borderRadius: 'var(--radius)',
          padding: '10px 12px',
          fontSize: '12px',
          color: 'var(--danger)',
          fontFamily: 'var(--font-sans)',
        }}>
          <span style={{ fontWeight: 600 }}>Blast radius: </span>
          {finding.blast_radius}
        </div>
      )}

      {/* Remediation — only for vulnerable/partial */}
      {!isResistant && remediation && (
        <div>
          <h4 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px', fontFamily: 'var(--font-sans)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Remediation
          </h4>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '12px', fontFamily: 'var(--font-sans)' }}>
            {remediation.summary}
          </p>
          {remediation.code_before && (
            <CodeBlock code={remediation.code_before} label="Before (vulnerable):" />
          )}
          {remediation.code_after && (
            <CodeBlock code={remediation.code_after} label="After (fixed):" />
          )}
          {remediation.architecture_note && (
            <div style={{
              borderLeft: '2px solid var(--accent-dim)',
              paddingLeft: '12px',
              paddingTop: '8px',
              paddingBottom: '8px',
              fontSize: '12px',
              color: 'var(--text-secondary)',
              marginTop: '12px',
              fontFamily: 'var(--font-sans)',
            }}>
              {remediation.architecture_note}
            </div>
          )}
          {remediation.references?.length > 0 && (
            <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {remediation.references.map((ref, i) => (
                <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                   style={{ fontSize: '11px', color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
                  {ref}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
