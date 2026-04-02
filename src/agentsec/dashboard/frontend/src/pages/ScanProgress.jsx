import { useParams, useNavigate } from 'react-router-dom';
import { useScanStream } from '../hooks/useScanStream';
import ProbeProgress from '../components/ProbeProgress';
import ErrorState from '../components/ErrorState';

export default function ScanProgress() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { events, status } = useScanStream(id);

  const completion = events.find(e => e.type === 'scan_complete');
  const scanErrorEvent = events.find(e => e.type === 'error');

  if (status === 'error') {
    const errorMessage = scanErrorEvent?.message || 'The scan encountered an unexpected error.';
    return (
      <div className="space-y-4">
        <ErrorState message={errorMessage} />
        <div className="text-center">
          <button
            onClick={() => navigate('/')}
            className="text-sm text-blue-400 hover:underline"
          >
            ← Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">
          {status === 'complete' ? 'Scan Complete' : 'Scanning...'}
        </h1>
        {status === 'complete' && (
          <button
            onClick={() => navigate(`/scans/${id}`)}
            className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded text-sm"
          >
            View Results →
          </button>
        )}
      </div>

      {completion && (
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-slate-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold">{completion.total}</div>
            <div className="text-xs text-slate-400">Total</div>
          </div>
          <div className="bg-slate-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-red-400">{completion.vulnerable}</div>
            <div className="text-xs text-slate-400">Vulnerable</div>
          </div>
          <div className="bg-slate-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-green-400">{completion.resistant}</div>
            <div className="text-xs text-slate-400">Resistant</div>
          </div>
          <div className="bg-slate-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-red-600">{completion.error}</div>
            <div className="text-xs text-slate-400">Errors</div>
          </div>
        </div>
      )}

      <ProbeProgress events={events} />
    </div>
  );
}
