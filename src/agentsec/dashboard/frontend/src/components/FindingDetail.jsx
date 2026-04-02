import CodeBlock from './CodeBlock';
import { SeverityBadge, StatusBadge } from './SeverityBadge';

export default function FindingDetail({ finding }) {
  const { evidence, remediation } = finding;

  return (
    <div className="space-y-4 pt-4 border-t border-slate-700">
      {/* Evidence */}
      {evidence && (
        <div>
          <h4 className="text-sm font-semibold text-slate-300 mb-2">Evidence</h4>
          <div className="bg-slate-900 rounded-lg p-4 space-y-3 text-sm border border-slate-700">
            <div>
              <span className="text-slate-500">Attack input: </span>
              <code className="text-red-300 break-all">{evidence.attack_input}</code>
            </div>
            <div>
              <span className="text-slate-500">Target agent: </span>
              <span className="text-blue-300">{evidence.target_agent}</span>
            </div>
            <div>
              <span className="text-slate-500">Response: </span>
              <code className="text-orange-300 break-all">{evidence.agent_response}</code>
            </div>
            {evidence.additional_context && (
              <div>
                <span className="text-slate-500">Context: </span>
                <span className="text-slate-300">{evidence.additional_context}</span>
              </div>
            )}
            {evidence.detection_method && (
              <div>
                <span className="text-slate-500">Detection: </span>
                <span className="text-slate-300">{evidence.detection_method}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Blast radius */}
      {finding.blast_radius && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-sm text-red-200">
          <span className="font-semibold">Blast radius: </span>
          {finding.blast_radius}
        </div>
      )}

      {/* Remediation */}
      {remediation && (
        <div>
          <h4 className="text-sm font-semibold text-slate-300 mb-2">Remediation</h4>
          <p className="text-sm text-slate-300 mb-3">{remediation.summary}</p>

          {remediation.code_before && (
            <CodeBlock code={remediation.code_before} label="Before (vulnerable):" />
          )}
          {remediation.code_after && (
            <CodeBlock code={remediation.code_after} label="After (fixed):" />
          )}
          {remediation.architecture_note && (
            <div className="bg-blue-500/10 border-l-2 border-blue-500 pl-4 py-2 text-sm text-slate-300 mt-3">
              {remediation.architecture_note}
            </div>
          )}
          {remediation.references?.length > 0 && (
            <div className="mt-2 space-y-1">
              {remediation.references.map((ref, i) => (
                <a key={i} href={ref} target="_blank" rel="noopener"
                   className="text-xs text-blue-400 hover:underline block">
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
