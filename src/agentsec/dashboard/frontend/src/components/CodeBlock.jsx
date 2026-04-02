import { useEffect, useRef } from 'react';
import hljs from 'highlight.js/lib/core';
import python from 'highlight.js/lib/languages/python';
import 'highlight.js/styles/github-dark.css';

hljs.registerLanguage('python', python);

export default function CodeBlock({ code, language = 'python', label }) {
  const codeRef = useRef(null);

  useEffect(() => {
    if (codeRef.current) {
      hljs.highlightElement(codeRef.current);
    }
  }, [code]);

  if (!code) return null;

  return (
    <div className="my-2">
      {label && (
        <div className="text-xs text-slate-500 mb-1 font-medium">{label}</div>
      )}
      <pre className="bg-slate-950 rounded-lg p-4 overflow-x-auto border border-slate-700">
        <code ref={codeRef} className={`language-${language} text-sm`}>
          {code}
        </code>
      </pre>
    </div>
  );
}
