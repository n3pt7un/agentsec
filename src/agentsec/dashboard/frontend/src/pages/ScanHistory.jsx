import { useState, useEffect } from 'react';
import ScanCard from '../components/ScanCard';
import { fetchScans } from '../api';

export default function ScanHistory() {
  const [scans, setScans] = useState([]);

  useEffect(() => {
    fetchScans(50).then(data => setScans(data.scans || []));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold">Scan History</h1>
      {scans.length === 0 ? (
        <p className="text-slate-400">No scans yet. Start one from the Dashboard.</p>
      ) : (
        <div className="space-y-2">
          {scans.map(scan => (
            <ScanCard key={scan.scan_id} scan={scan} />
          ))}
        </div>
      )}
    </div>
  );
}
