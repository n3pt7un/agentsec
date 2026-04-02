import { useState, useEffect } from 'react';

export function useScanStream(scanId) {
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState('connecting');

  useEffect(() => {
    if (!scanId) return;

    const source = new EventSource(`/api/scans/${scanId}/stream`);
    setStatus('streaming');

    source.addEventListener('probe_started', (e) => {
      const data = JSON.parse(e.data);
      setEvents(prev => [...prev, { type: 'started', ...data }]);
    });

    source.addEventListener('probe_completed', (e) => {
      const data = JSON.parse(e.data);
      setEvents(prev => [...prev, { type: 'completed', ...data }]);
    });

    source.addEventListener('scan_complete', (e) => {
      const data = JSON.parse(e.data);
      setEvents(prev => [...prev, { type: 'scan_complete', ...data }]);
      setStatus('complete');
      source.close();
    });

    source.addEventListener('scan_error', (e) => {
      const data = JSON.parse(e.data);
      setEvents(prev => [...prev, { type: 'error', ...data }]);
      setStatus('error');
      source.close();
    });

    source.onerror = () => {
      setStatus('error');
      source.close();
    };

    return () => source.close();
  }, [scanId]);

  return { events, status };
}
