const BASE = '';

export async function fetchTargets() {
  const res = await fetch(`${BASE}/api/targets`);
  return res.json();
}

export async function fetchProbes() {
  const res = await fetch(`${BASE}/api/probes`);
  return res.json();
}

export async function fetchScans(limit = 20) {
  const res = await fetch(`${BASE}/api/scans?limit=${limit}`);
  return res.json();
}

export async function fetchScan(scanId) {
  const res = await fetch(`${BASE}/api/scans/${scanId}`);
  return res.json();
}

export async function startScan(config) {
  const res = await fetch(`${BASE}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  return res.json();
}

export async function deleteScan(scanId) {
  const res = await fetch(`${BASE}/api/scans/${scanId}`, { method: 'DELETE' });
  return res.json();
}

export async function applyOverride(scanId, probeId, body) {
  const res = await fetch(`/api/scans/${scanId}/findings/${encodeURIComponent(probeId)}/override`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function removeOverride(scanId, probeId) {
  const res = await fetch(`/api/scans/${scanId}/findings/${encodeURIComponent(probeId)}/override`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function exportScan(scanId, format) {
  const res = await fetch(`/api/scans/${scanId}/export?format=${format}`);
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `scan-${scanId}.${format}`;
  a.click();
  URL.revokeObjectURL(url);
}

export async function exportScans(scanIds, format) {
  const res = await fetch('/api/scans/export', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scan_ids: scanIds, format }),
  });
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const date = new Date().toISOString().slice(0, 10);
  a.download = `agentsec-export-${date}.zip`;
  a.click();
  URL.revokeObjectURL(url);
}
