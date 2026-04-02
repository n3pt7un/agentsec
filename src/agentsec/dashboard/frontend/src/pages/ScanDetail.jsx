import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { fetchScan } from '../api';

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);

  useEffect(() => {
    fetchScan(id).then(setScan);
  }, [id]);

  if (!scan) return <div className="text-slate-400">Loading...</div>;

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold">Scan: {scan.target}</h1>
      <pre className="bg-slate-800 p-4 rounded text-xs overflow-auto max-h-96">
        {JSON.stringify(scan, null, 2)}
      </pre>
    </div>
  );
}
