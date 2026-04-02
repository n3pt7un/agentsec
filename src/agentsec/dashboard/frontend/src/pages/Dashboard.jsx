import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import ScanForm from '../components/ScanForm';
import ScanCard from '../components/ScanCard';
import { SkeletonCard } from '../components/LoadingSkeleton';
import ErrorState from '../components/ErrorState';
import EmptyState from '../components/EmptyState';
import { startScan, fetchScans } from '../api';
import { useSettings } from '../hooks/useSettings';

export default function Dashboard() {
  const navigate = useNavigate();
  const { settings } = useSettings();
  const [loading, setLoading] = useState(false);
  const [scanError, setScanError] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [scansLoading, setScansLoading] = useState(true);
  const [scansError, setScansError] = useState(null);

  const loadScans = useCallback(() => {
    setScansLoading(true);
    setScansError(null);
    fetchScans(5)
      .then(data => setRecentScans(data.scans || []))
      .catch(err => setScansError(err.message || 'Failed to load recent scans'))
      .finally(() => setScansLoading(false));
  }, []);

  useEffect(() => {
    loadScans();
  }, [loadScans]);

  const handleScan = async (config) => {
    setLoading(true);
    setScanError(null);
    try {
      const mergedConfig = {
        ...config,
        llm_model: settings.llm_model,
        openrouter_api_key: settings.openrouter_api_key || undefined,
      };
      const data = await startScan(mergedConfig);
      navigate(`/scans/${data.scan_id}/progress`);
    } catch (err) {
      setScanError(err.message || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      <ScanForm onSubmit={handleScan} loading={loading} />

      {scanError && (
        <ErrorState message={scanError} onRetry={null} />
      )}

      <div>
        <h2 className="text-lg font-semibold mb-3">Recent Scans</h2>

        {scansLoading && (
          <div className="space-y-2">
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
          </div>
        )}

        {!scansLoading && scansError && (
          <ErrorState message={scansError} onRetry={loadScans} />
        )}

        {!scansLoading && !scansError && recentScans.length === 0 && (
          <EmptyState
            title="No scans yet"
            description="Run your first scan to see results here."
            actionLabel="Start Scanning"
            actionTo="/"
          />
        )}

        {!scansLoading && !scansError && recentScans.length > 0 && (
          <div className="space-y-2">
            {recentScans.map(scan => (
              <ScanCard key={scan.scan_id} scan={scan} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
