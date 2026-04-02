import { useEffect, useRef, useState } from 'react';
import { IconCopy, IconCheck } from '@tabler/icons-react';
import hljs from 'highlight.js/lib/core';
import python from 'highlight.js/lib/languages/python';
import 'highlight.js/styles/github-dark.css';

hljs.registerLanguage('python', python);

export default function CodeBlock({ code, language = 'python', label }) {
  const codeRef = useRef(null);
  const [copied, setCopied] = useState(false);
  const [copyHovered, setCopyHovered] = useState(false);

  useEffect(() => {
    if (codeRef.current) {
      delete codeRef.current.dataset.highlighted;
      hljs.highlightElement(codeRef.current);
    }
  }, [code]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard not available or permission denied
    }
  };

  if (!code) return null;

  return (
    <div style={{ margin: '8px 0' }}>
      {label && (
        <div style={{
          fontSize: '11px',
          color: 'var(--text-muted)',
          marginBottom: '4px',
          fontFamily: 'var(--font-mono)',
        }}>
          {label}
        </div>
      )}
      <div style={{ position: 'relative' }}>
        <pre style={{
          background: '#0d1117',
          borderRadius: 'var(--radius)',
          padding: '14px',
          overflowX: 'auto',
          border: '1px solid var(--border)',
          margin: 0,
        }}>
          <code ref={codeRef} className={`language-${language}`} style={{ fontSize: '12px' }}>
            {code}
          </code>
        </pre>
        <button
          onClick={handleCopy}
          title="Copy"
          aria-label="Copy code"
          onMouseEnter={() => setCopyHovered(true)}
          onMouseLeave={() => setCopyHovered(false)}
          style={{
            position: 'absolute',
            top: '8px',
            right: '8px',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: copied ? 'var(--accent)' : (copyHovered ? 'var(--accent)' : 'var(--text-muted)'),
            padding: '2px',
            display: 'flex',
            alignItems: 'center',
            transition: 'color 0.1s',
          }}
        >
          {copied ? <IconCheck size={14} stroke={2} /> : <IconCopy size={14} stroke={1.5} />}
        </button>
      </div>
    </div>
  );
}
