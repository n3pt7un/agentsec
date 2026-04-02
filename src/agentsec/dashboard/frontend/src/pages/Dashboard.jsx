import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import ScanForm from '../components/ScanForm';
import ScanCard from '../components/ScanCard';
import { startScan, fetchScans } from '../api';

export default function Dashboard() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [recentScans, setRecentScans] = useState([]);

  useEffect(() => {
    fetchScans(5).then(data => setRecentScans(data.scans || []));
  }, []);

  const handleScan = async (config) => {
    setLoading(true);
    try {
      const data = await startScan(config);
      navigate(`/scans/${data.scan_id}/progress`);
    } catch (err) {
      console.error('Failed to start scan:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      <ScanForm onSubmit={handleScan} loading={loading} />

      {recentScans.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-3">Recent Scans</h2>
          <div className="space-y-2">
            {recentScans.map(scan => (
              <ScanCard key={scan.scan_id} scan={scan} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
